//! Thin FFI wrapper around [`minhook`](https://github.com/TsudaKageyu/minhook).
#![allow(dead_code, non_snake_case, non_camel_case_types, missing_docs)]

use std::ffi::c_void;
use std::mem;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicPtr, AtomicU8, Ordering};

use tracing::{error, warn};
use windows::Win32::System::Memory::{VirtualProtect, PAGE_PROTECTION_FLAGS, PAGE_READWRITE};

#[allow(non_camel_case_types)]
#[must_use]
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MH_STATUS {
    /// Unknown error. Should not be returned.
    MH_UNKNOWN = -1,
    /// Successful.
    MH_OK = 0,
    /// MinHook is already initialized.
    MH_ERROR_ALREADY_INITIALIZED,
    /// MinHook is not initialized yet, or already uninitialized.
    MH_ERROR_NOT_INITIALIZED,
    /// The hook for the specified target function is already created.
    MH_ERROR_ALREADY_CREATED,
    /// The hook for the specified target function is not created yet.
    MH_ERROR_NOT_CREATED,
    /// The hook for the specified target function is already enabled.
    MH_ERROR_ENABLED,
    /// The hook for the specified target function is not enabled yet, or
    /// already disabled.
    MH_ERROR_DISABLED,
    /// The specified pointer is invalid. It points the address of non-allocated
    /// and/or non-executable region.
    MH_ERROR_NOT_EXECUTABLE,
    /// The specified target function cannot be hooked.
    MH_ERROR_UNSUPPORTED_FUNCTION,
    /// Failed to allocate memory.
    MH_ERROR_MEMORY_ALLOC,
    /// Failed to change the memory protection.
    MH_ERROR_MEMORY_PROTECT,
    /// The specified module is not loaded.
    MH_ERROR_MODULE_NOT_FOUND,
    /// The specified function is not found.
    MH_ERROR_FUNCTION_NOT_FOUND,
}

extern "system" {
    pub fn MH_Initialize() -> MH_STATUS;
    pub fn MH_Uninitialize() -> MH_STATUS;
    pub fn MH_CreateHook(
        pTarget: *mut c_void,
        pDetour: *mut c_void,
        ppOriginal: *mut *mut c_void,
    ) -> MH_STATUS;
    pub fn MH_EnableHook(pTarget: *mut c_void) -> MH_STATUS;
    pub fn MH_QueueEnableHook(pTarget: *mut c_void) -> MH_STATUS;
    pub fn MH_DisableHook(pTarget: *mut c_void) -> MH_STATUS;
    pub fn MH_QueueDisableHook(pTarget: *mut c_void) -> MH_STATUS;
    pub fn MH_ApplyQueued() -> MH_STATUS;
}

impl MH_STATUS {
    pub fn ok_context(self, context: &str) -> Result<(), MH_STATUS> {
        if self == MH_STATUS::MH_OK {
            Ok(())
        } else {
            error!("{context}: {self:?}");
            Err(self)
        }
    }

    pub fn ok(self) -> Result<(), MH_STATUS> {
        if self == MH_STATUS::MH_OK {
            Ok(())
        } else {
            Err(self)
        }
    }
}

/// How hooks are put in place.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HookMethod {
    /// Patch the start of the hooked function to jump to the hook (with
    /// minhook). Every call to the function is hooked, whichever pointer it's
    /// called through.
    #[default]
    Inline,
    /// Replace the function's pointer in the vtable it was found through.
    /// Only calls through that vtable are hooked, but other software that
    /// patches the start of the function (e.g. RivaTuner Statistics Server,
    /// which puts its own saved bytes back over it) can't undo the hook.
    VTable,
}

static HOOK_METHOD: AtomicU8 = AtomicU8::new(HookMethod::Inline as u8);

/// Set how hooks made from now on are put in place.
pub fn set_hook_method(method: HookMethod) {
    HOOK_METHOD.store(method as u8, Ordering::SeqCst);
}

/// How hooks made from now on are put in place.
pub fn hook_method() -> HookMethod {
    if HOOK_METHOD.load(Ordering::SeqCst) == HookMethod::VTable as u8 {
        HookMethod::VTable
    } else {
        HookMethod::Inline
    }
}

// What a hook replaces: the start of a function, or a pointer to it in a vtable
enum Target {
    Function(*mut c_void),
    VTableSlot(*mut *mut c_void),
}

/// Structure that holds original address, hook function address, and trampoline
/// address for a given hook.
pub struct MhHook {
    target: Target,
    hook_impl: *mut c_void,
    trampoline: *mut c_void,
}

impl MhHook {
    /// # Safety
    ///
    /// Most definitely undefined behavior.
    pub unsafe fn new(addr: *mut c_void, hook_impl: *mut c_void) -> Result<Self, MH_STATUS> {
        let mut trampoline = null_mut();
        MH_CreateHook(addr, hook_impl, &mut trampoline).ok_context("MH_CreateHook")?;

        Ok(Self { target: Target::Function(addr), hook_impl, trampoline })
    }

    /// Hook the function a vtable slot points at, the way [`hook_method`] says:
    /// its start, or the slot itself. The trampoline of a vtable hook is the
    /// pointer that was in the slot.
    ///
    /// # Safety
    ///
    /// `slot` must be a pointer in a vtable that lives as long as the hook.
    pub unsafe fn new_for_slot(
        slot: *mut *mut c_void,
        hook_impl: *mut c_void,
    ) -> Result<Self, MH_STATUS> {
        match hook_method() {
            HookMethod::Inline => Self::new(*slot, hook_impl),
            HookMethod::VTable => {
                Ok(Self { target: Target::VTableSlot(slot), hook_impl, trampoline: *slot })
            },
        }
    }

    pub fn trampoline(&self) -> *mut c_void {
        self.trampoline
    }

    /// Queue enabling an inline hook, or enable a vtable hook now.
    ///
    /// # Safety
    ///
    /// Most definitely undefined behavior.
    pub unsafe fn queue_enable(&self) -> Result<(), MH_STATUS> {
        match self.target {
            Target::Function(addr) => {
                MH_QueueEnableHook(addr).ok_context("MH_QueueEnableHook")
            },
            Target::VTableSlot(slot) => write_slot(slot, self.trampoline, self.hook_impl),
        }
    }

    /// Queue disabling an inline hook, or disable a vtable hook now.
    ///
    /// # Safety
    ///
    /// Most definitely undefined behavior.
    pub unsafe fn queue_disable(&self) -> Result<(), MH_STATUS> {
        match self.target {
            Target::Function(addr) => {
                MH_QueueDisableHook(addr).ok_context("MH_QueueDisableHook")
            },
            Target::VTableSlot(slot) => write_slot(slot, self.hook_impl, self.trampoline),
        }
    }
}

// Point a vtable slot at `to`, expecting it to point at `from`. If something
// else has replaced it since, it's overwritten anyway: leaving a pointer that
// leads back into a library being unloaded would crash.
unsafe fn write_slot(
    slot: *mut *mut c_void,
    from: *mut c_void,
    to: *mut c_void,
) -> Result<(), MH_STATUS> {
    let mut old_protect = PAGE_PROTECTION_FLAGS::default();
    if VirtualProtect(slot as _, mem::size_of::<*mut c_void>(), PAGE_READWRITE, &mut old_protect)
        .is_err()
    {
        error!("Couldn't make vtable slot {slot:p} writable");
        return Err(MH_STATUS::MH_ERROR_MEMORY_PROTECT);
    }
    let previous =
        (*(slot as *const AtomicPtr<c_void>)).swap(to, Ordering::SeqCst);
    if previous != from {
        warn!("Vtable slot {slot:p} was {previous:p}, not {from:p}; replaced it with {to:p}");
    }
    let mut unused = PAGE_PROTECTION_FLAGS::default();
    let _ = VirtualProtect(slot as _, mem::size_of::<*mut c_void>(), old_protect, &mut unused);
    Ok(())
}
