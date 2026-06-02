//! Layer-4 blocking via eBPF/XDP.
//!
//! Mirrors the Go `internal/xdp` package. The eBPF program itself is the exact
//! same bytecode shipped by the Go build (`bpf_bpfel.o`), loaded at runtime with
//! `aya` instead of `cilium/ebpf`. This keeps the kernel-side behaviour identical
//! and avoids needing a BPF toolchain at build time.
//!
//! XDP is Linux-only and gated behind the `xdp` cargo feature. On every other
//! platform / when the feature is disabled, a no-op blocker is used and all
//! block/unblock calls do nothing (matching the Go behaviour when
//! `PROXY_XDP_INTERFACE` is unset).

#[derive(Clone, Copy, Default, Debug)]
pub struct Stats {
    pub allowed: u64,
    pub blocked: u64,
}

/// Interface for an IP blocker (like XDP).
pub trait Blocker: Send + Sync {
    fn block_ip(&self, ip: &str) -> Result<(), String>;
    fn unblock_ip(&self, ip: &str) -> Result<(), String>;
    fn get_stats(&self) -> Result<Stats, String>;
}

/// Convert a dotted IPv4 string into the u32 key used by the eBPF blocklist map.
/// Matches the Go encoding: `ip[0] | ip[1]<<8 | ip[2]<<16 | ip[3]<<24`.
#[cfg(all(target_os = "linux", feature = "xdp"))]
fn ipv4_key(ip: &str) -> Option<u32> {
    let addr: std::net::Ipv4Addr = ip.parse().ok()?;
    let o = addr.octets();
    Some((o[0] as u32) | (o[1] as u32) << 8 | (o[2] as u32) << 16 | (o[3] as u32) << 24)
}

// ── Linux + feature `xdp`: real aya-backed implementation ────────────────────
#[cfg(all(target_os = "linux", feature = "xdp"))]
mod imp {
    use super::{ipv4_key, Blocker, Stats};
    use aya::maps::{Array, HashMap as AyaHashMap};
    use aya::programs::{Xdp, XdpFlags};
    use aya::Ebpf;
    use std::sync::Mutex;

    // Precompiled eBPF object (same bytecode as the Go build).
    static BPF_OBJECT: &[u8] = include_bytes!("bpf/xdp_bpfel.o");

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct BpfStats {
        allowed: u64,
        blocked: u64,
    }
    unsafe impl aya::Pod for BpfStats {}

    pub struct XdpBlocker {
        ebpf: Mutex<Ebpf>,
    }

    impl XdpBlocker {
        pub fn init(iface: &str) -> Result<Self, String> {
            let mut ebpf = Ebpf::load(BPF_OBJECT).map_err(|e| format!("load BPF objects: {e}"))?;
            let program: &mut Xdp = ebpf
                .program_mut("xdp_drop_func")
                .ok_or_else(|| "program xdp_drop_func not found".to_string())?
                .try_into()
                .map_err(|e| format!("program is not XDP: {e}"))?;
            program.load().map_err(|e| format!("load program: {e}"))?;
            program
                .attach(iface, XdpFlags::default())
                .map_err(|e| format!("attach XDP to {iface}: {e}"))?;
            Ok(XdpBlocker {
                ebpf: Mutex::new(ebpf),
            })
        }
    }

    impl Blocker for XdpBlocker {
        fn block_ip(&self, ip: &str) -> Result<(), String> {
            let key = ipv4_key(ip).ok_or_else(|| format!("invalid IPv4 address: {ip}"))?;
            let mut ebpf = self.ebpf.lock().unwrap();
            let mut blocklist: AyaHashMap<_, u32, u8> =
                AyaHashMap::try_from(ebpf.map_mut("blocklist").ok_or("blocklist map missing")?)
                    .map_err(|e| e.to_string())?;
            blocklist.insert(key, 1u8, 0).map_err(|e| e.to_string())
        }

        fn unblock_ip(&self, ip: &str) -> Result<(), String> {
            let key = ipv4_key(ip).ok_or_else(|| format!("invalid IPv4 address: {ip}"))?;
            let mut ebpf = self.ebpf.lock().unwrap();
            let mut blocklist: AyaHashMap<_, u32, u8> =
                AyaHashMap::try_from(ebpf.map_mut("blocklist").ok_or("blocklist map missing")?)
                    .map_err(|e| e.to_string())?;
            blocklist.remove(&key).map_err(|e| e.to_string())
        }

        fn get_stats(&self) -> Result<Stats, String> {
            let ebpf = self.ebpf.lock().unwrap();
            let stats: Array<_, BpfStats> =
                Array::try_from(ebpf.map("xdp_stats").ok_or("xdp_stats map missing")?)
                    .map_err(|e| e.to_string())?;
            let s = stats.get(&0, 0).map_err(|e| e.to_string())?;
            Ok(Stats {
                allowed: s.allowed,
                blocked: s.blocked,
            })
        }
    }

    pub fn init_xdp(iface: &str) -> Result<XdpBlocker, String> {
        XdpBlocker::init(iface)
    }
}

#[cfg(all(target_os = "linux", feature = "xdp"))]
pub use imp::{init_xdp, XdpBlocker};

/// Initialise XDP. On non-Linux / feature-disabled builds this always errors,
/// so the caller leaves the blocker unset (no-op), exactly like Go when the
/// interface is not configured.
#[cfg(not(all(target_os = "linux", feature = "xdp")))]
#[allow(dead_code)]
pub fn init_xdp(_iface: &str) -> Result<NoopBlocker, String> {
    Err("XDP support not compiled in (enable the `xdp` feature on Linux)".to_string())
}

/// No-op blocker used when XDP is unavailable.
#[allow(dead_code)]
pub struct NoopBlocker;

impl Blocker for NoopBlocker {
    fn block_ip(&self, _ip: &str) -> Result<(), String> {
        Ok(())
    }
    fn unblock_ip(&self, _ip: &str) -> Result<(), String> {
        Ok(())
    }
    fn get_stats(&self) -> Result<Stats, String> {
        Ok(Stats::default())
    }
}
