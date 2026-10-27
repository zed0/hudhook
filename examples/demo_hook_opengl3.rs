use hudhook::*;

mod support;

/// Entry point created by the `hudhook` library.
///
/// # Safety
///
/// haha
#[no_mangle]
pub unsafe extern "system" fn DllMain(
    hmodule: ::hudhook::windows::Win32::Foundation::HINSTANCE,
    reason: u32,
    _: *mut ::std::ffi::c_void,
) -> i32 {
    if reason == ::hudhook::windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH {
        support::setup_tracing();
        ::hudhook::tracing::trace!("DllMain()");
        let hmodule_raw = hmodule.0 as usize;
        ::std::thread::spawn(move || {
            let hmodule = ::hudhook::windows::Win32::Foundation::HINSTANCE(hmodule_raw as _);
            if let Err(e) = ::hudhook::Hudhook::builder()
                .with::<hooks::opengl3::ImguiOpenGl3Hooks>(support::HookExample::new())
                .with_hmodule(hmodule)
                .build()
                .apply()
            {
                ::hudhook::tracing::error!("Couldn't apply hooks: {e:?}");
                ::hudhook::eject();
            }
        });
    }
    // DllMain returns a BOOL: without one the loader reads whatever is left in the
    // return register, and if that happens to be 0 it unloads the DLL again, while
    // the thread started above is still to run.
    1
}
