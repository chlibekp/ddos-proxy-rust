//! Layer-4 blocking via eBPF/XDP.
//!
//! Mirrors the Go `internal/xdp` package. The eBPF program (`src/bpf/xdp.c`) is
//! the same C source/logic as the Go build, compiled fresh with clang by
//! `build.rs` (BTF maps so `aya` can load it) and attached at runtime via `aya`
//! instead of `cilium/ebpf`. The kernel-side behaviour is identical.
//!
//! XDP is Linux-only and gated behind the `xdp` cargo feature. On every other
//! platform / when the feature is disabled, a no-op blocker is used and all
//! block/unblock calls do nothing (matching the Go behaviour when
//! `PROXY_XDP_INTERFACE` is unset).

/// Number of leading payload bytes captured per fingerprint. Must match
/// `FP_SAMPLE_LEN` in `src/bpf/xdp.c`.
#[allow(dead_code)] // only read by the Linux+xdp implementation
pub const FP_SAMPLE_LEN: usize = 16;

#[derive(Clone, Copy, Default, Debug)]
pub struct Stats {
    pub allowed: u64,
    pub blocked: u64,
    /// Per-reason breakdown of the `blocked` total (see `src/bpf/xdp.c`).
    pub drop_blocklist: u64,
    pub drop_udp: u64,
    pub drop_tcp_malformed: u64,
    pub drop_http_invalid: u64,
    pub drop_tls_invalid: u64,
    pub drop_icmp: u64,
    pub drop_bad_flags: u64,
    pub drop_fragment: u64,
    pub drop_amplify: u64,
    pub drop_syn_flood: u64,
    /// RST-cookie SYN-ACK challenges emitted (XDP_TX) while under SYN flood.
    pub syn_challenged: u64,
    /// RST cookies validated, whitelisting the source IP.
    pub syn_validated: u64,
}

/// A captured byte signature of repeatedly-dropped packets: the first
/// [`FP_SAMPLE_LEN`] bytes of the payload and how often that pattern was seen.
#[derive(Clone, Debug)]
pub struct Fingerprint {
    /// FNV-1a hash of the sampled bytes (the map key).
    pub hash: u32,
    /// How many dropped packets carried this exact byte prefix.
    pub count: u64,
    /// The captured leading bytes (up to [`FP_SAMPLE_LEN`]).
    pub bytes: Vec<u8>,
}

/// Interface for an IP blocker (like XDP).
pub trait Blocker: Send + Sync {
    fn block_ip(&self, ip: &str) -> Result<(), String>;
    fn unblock_ip(&self, ip: &str) -> Result<(), String>;
    fn get_stats(&self) -> Result<Stats, String>;
    /// Return the most frequently-seen dropped-payload fingerprints, highest
    /// count first, capped at `n`.
    fn top_fingerprints(&self, n: usize) -> Result<Vec<Fingerprint>, String>;
    /// Drop all recorded fingerprints (called when an attack window ends so the
    /// next attack starts with a clean signature set).
    fn clear_fingerprints(&self) -> Result<(), String>;
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
    use super::{ipv4_key, Blocker, Fingerprint, Stats, SynAuthConfig, FP_SAMPLE_LEN};
    use aya::maps::{Array, HashMap as AyaHashMap};
    use aya::programs::{Xdp, XdpFlags};
    use aya::Ebpf;
    use std::sync::Mutex;

    // eBPF object compiled from src/bpf/xdp.c by build.rs (clang, BTF maps).
    static BPF_OBJECT: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/xdp.o"));

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct BpfStats {
        allowed: u64,
        blocked: u64,
        drop_blocklist: u64,
        drop_udp: u64,
        drop_tcp_malformed: u64,
        drop_http_invalid: u64,
        drop_tls_invalid: u64,
        drop_icmp: u64,
        drop_bad_flags: u64,
        drop_fragment: u64,
        drop_amplify: u64,
        drop_syn_flood: u64,
        syn_challenged: u64,
        syn_validated: u64,
    }
    unsafe impl aya::Pod for BpfStats {}

    // Layout must match `struct xdp_config` in src/bpf/xdp.c:
    //   __u32 syn_auth_enabled; __u32 syn_auth_pps; __u32 cookie_secret; __u32 _pad;
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct BpfConfig {
        syn_auth_enabled: u32,
        syn_auth_pps: u32,
        cookie_secret: u32,
        _pad: u32,
    }
    unsafe impl aya::Pod for BpfConfig {}

    // Layout must match `struct fingerprint` in src/bpf/xdp.c:
    //   __u64 count; __u32 len; __u8 bytes[16];  (size 32, align 8)
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct BpfFingerprint {
        count: u64,
        len: u32,
        bytes: [u8; FP_SAMPLE_LEN],
    }
    unsafe impl aya::Pod for BpfFingerprint {}

    pub struct XdpBlocker {
        ebpf: Mutex<Ebpf>,
    }

    impl XdpBlocker {
        pub fn init(iface: &str, syn_auth: SynAuthConfig) -> Result<Self, String> {
            let mut ebpf = Ebpf::load(BPF_OBJECT).map_err(|e| format!("load BPF objects: {e}"))?;

            // Populate the runtime config map before attaching so the program
            // sees the SYN-auth settings (and a fresh random cookie secret) from
            // its very first packet.
            {
                let mut cfg_map: Array<_, BpfConfig> =
                    Array::try_from(ebpf.map_mut("xdp_cfg").ok_or("xdp_cfg map missing")?)
                        .map_err(|e| e.to_string())?;
                let cfg = BpfConfig {
                    syn_auth_enabled: syn_auth.enabled as u32,
                    syn_auth_pps: syn_auth.pps_threshold,
                    cookie_secret: rand::random::<u32>(),
                    _pad: 0,
                };
                cfg_map.set(0, cfg, 0).map_err(|e| e.to_string())?;
            }

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
                drop_blocklist: s.drop_blocklist,
                drop_udp: s.drop_udp,
                drop_tcp_malformed: s.drop_tcp_malformed,
                drop_http_invalid: s.drop_http_invalid,
                drop_tls_invalid: s.drop_tls_invalid,
                drop_icmp: s.drop_icmp,
                drop_bad_flags: s.drop_bad_flags,
                drop_fragment: s.drop_fragment,
                drop_amplify: s.drop_amplify,
                drop_syn_flood: s.drop_syn_flood,
                syn_challenged: s.syn_challenged,
                syn_validated: s.syn_validated,
            })
        }

        fn top_fingerprints(&self, n: usize) -> Result<Vec<Fingerprint>, String> {
            let ebpf = self.ebpf.lock().unwrap();
            let map: AyaHashMap<_, u32, BpfFingerprint> = AyaHashMap::try_from(
                ebpf.map("fingerprints").ok_or("fingerprints map missing")?,
            )
            .map_err(|e| e.to_string())?;

            let mut out: Vec<Fingerprint> = Vec::new();
            for entry in map.iter() {
                let (hash, fp) = entry.map_err(|e| e.to_string())?;
                let len = (fp.len as usize).min(FP_SAMPLE_LEN);
                out.push(Fingerprint {
                    hash,
                    count: fp.count,
                    bytes: fp.bytes[..len].to_vec(),
                });
            }
            out.sort_by(|a, b| b.count.cmp(&a.count));
            out.truncate(n);
            Ok(out)
        }

        fn clear_fingerprints(&self) -> Result<(), String> {
            let mut ebpf = self.ebpf.lock().unwrap();
            let mut map: AyaHashMap<_, u32, BpfFingerprint> = AyaHashMap::try_from(
                ebpf.map_mut("fingerprints").ok_or("fingerprints map missing")?,
            )
            .map_err(|e| e.to_string())?;
            let keys: Vec<u32> = map.keys().filter_map(|k| k.ok()).collect();
            for k in keys {
                let _ = map.remove(&k);
            }
            Ok(())
        }
    }

    pub fn init_xdp(iface: &str, syn_auth: SynAuthConfig) -> Result<XdpBlocker, String> {
        XdpBlocker::init(iface, syn_auth)
    }
}

#[cfg(all(target_os = "linux", feature = "xdp"))]
pub use imp::{init_xdp, XdpBlocker};

/// Runtime knobs for the XDP SYN-cookie (RST-cookie) authentication layer.
#[derive(Clone, Copy, Debug)]
pub struct SynAuthConfig {
    /// Master switch (`PROXY_XDP_SYN_AUTH`). When false the kernel program keeps
    /// its previous behaviour (per-source SYN rate limiting only).
    pub enabled: bool,
    /// Aggregate SYN/s that engages cookie challenging (`PROXY_XDP_SYN_AUTH_PPS`).
    pub pps_threshold: u32,
}

/// Initialise XDP. On non-Linux / feature-disabled builds this always errors,
/// so the caller leaves the blocker unset (no-op), exactly like Go when the
/// interface is not configured.
#[cfg(not(all(target_os = "linux", feature = "xdp")))]
#[allow(dead_code)]
pub fn init_xdp(_iface: &str, _syn_auth: SynAuthConfig) -> Result<NoopBlocker, String> {
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
    fn top_fingerprints(&self, _n: usize) -> Result<Vec<Fingerprint>, String> {
        Ok(Vec::new())
    }
    fn clear_fingerprints(&self) -> Result<(), String> {
        Ok(())
    }
}
