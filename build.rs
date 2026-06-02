use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=src/bpf/xdp.c");
    println!("cargo:rerun-if-changed=build.rs");

    // Only compile the eBPF object when the `xdp` feature is enabled and we are
    // targeting Linux. Other builds skip this entirely (no clang needed).
    if env::var_os("CARGO_FEATURE_XDP").is_none() {
        return;
    }
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        return;
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    let obj = out_dir.join("xdp.o");

    // Multiarch include dir for <asm/*.h> pulled in by the linux UAPI headers.
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let triple_inc = match arch.as_str() {
        "x86_64" => "/usr/include/x86_64-linux-gnu",
        "aarch64" => "/usr/include/aarch64-linux-gnu",
        other => {
            // Best-effort fallback.
            eprintln!("cargo:warning=unrecognized target arch '{other}' for eBPF include path");
            "/usr/include"
        }
    };

    let clang = env::var("CLANG").unwrap_or_else(|_| "clang".to_string());
    let status = Command::new(&clang)
        .args(["-O2", "-g", "-Wall", "-target", "bpfel", "-c"])
        .arg("src/bpf/xdp.c")
        .arg("-o")
        .arg(&obj)
        .arg("-I/usr/include")
        .arg(format!("-I{triple_inc}"))
        .status()
        .unwrap_or_else(|e| panic!("failed to run '{clang}' to compile eBPF (is clang installed?): {e}"));

    assert!(status.success(), "clang failed to compile src/bpf/xdp.c");
}
