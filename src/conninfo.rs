//! Connection-level TCP introspection backing the `X-Tcp` response header and
//! the connection components of `Server-Timing`.

use std::time::{Duration, Instant};

/// Per-connection metadata captured at accept time and shared (via `Arc`) by
/// every request served on the connection.
pub struct ConnInfo {
    /// Proxy-side (local) socket address.
    pub local_addr: String,
    /// When the TCP connection was accepted.
    pub accepted_at: Instant,
    /// TLS handshake duration (TLS listener only).
    pub tls_handshake: Option<Duration>,
    /// Raw socket fd used to query live `TCP_INFO` per request (Linux). The
    /// connection task owns the stream and requests only run while it is open,
    /// so the fd outlives any `ReqCtx` that references it.
    #[cfg(unix)]
    pub fd: std::os::unix::io::RawFd,
}

impl ConnInfo {
    pub fn from_stream(stream: &tokio::net::TcpStream) -> Self {
        #[cfg(unix)]
        use std::os::unix::io::AsRawFd;
        ConnInfo {
            local_addr: stream.local_addr().map(|a| a.to_string()).unwrap_or_default(),
            accepted_at: Instant::now(),
            tls_handshake: None,
            #[cfg(unix)]
            fd: stream.as_raw_fd(),
        }
    }
}

/// Render the `X-Tcp` header value: peer/local addresses and connection age
/// always; live kernel `TCP_INFO` (RTT, cwnd, MSS, retransmits, ...) on Linux.
pub fn x_tcp_value(conn: Option<&ConnInfo>, remote_addr: &str) -> String {
    let mut parts = vec![format!("client={remote_addr}")];
    if let Some(c) = conn {
        if !c.local_addr.is_empty() {
            parts.push(format!("server={}", c.local_addr));
        }
        parts.push(format!("age_ms={}", c.accepted_at.elapsed().as_millis()));
        #[cfg(target_os = "linux")]
        if let Some(ti) = tcp_info(c.fd) {
            push_tcp_info(&mut parts, &ti);
        }
    }
    parts.join("; ")
}

/// Prefix of the kernel's `struct tcp_info` (linux/tcp.h), through
/// `tcpi_total_retrans`. The kernel copies `min(len, sizeof(kernel struct))`
/// bytes, so a shorter struct is fine and older kernels leave trailing fields
/// zeroed. Field order and widths must match the kernel ABI.
#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct TcpInfo {
    state: u8,
    ca_state: u8,
    retransmits: u8,
    probes: u8,
    backoff: u8,
    options: u8,
    /// Bitfields: `snd_wscale : 4, rcv_wscale : 4` (snd in the low nibble).
    wscale: u8,
    delivery_rate_app_limited: u8,
    rto: u32,
    ato: u32,
    snd_mss: u32,
    rcv_mss: u32,
    unacked: u32,
    sacked: u32,
    lost: u32,
    retrans: u32,
    fackets: u32,
    last_data_sent: u32,
    last_ack_sent: u32,
    last_data_recv: u32,
    last_ack_recv: u32,
    pmtu: u32,
    rcv_ssthresh: u32,
    rtt: u32,
    rttvar: u32,
    snd_ssthresh: u32,
    snd_cwnd: u32,
    advmss: u32,
    reordering: u32,
    rcv_rtt: u32,
    rcv_space: u32,
    total_retrans: u32,
}

#[cfg(target_os = "linux")]
fn tcp_info(fd: std::os::unix::io::RawFd) -> Option<TcpInfo> {
    let mut info = TcpInfo::default();
    let mut len = std::mem::size_of::<TcpInfo>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_INFO,
            &mut info as *mut TcpInfo as *mut libc::c_void,
            &mut len,
        )
    };
    (rc == 0).then_some(info)
}

#[cfg(target_os = "linux")]
fn push_tcp_info(parts: &mut Vec<String>, ti: &TcpInfo) {
    parts.push(format!("state={}", tcp_state_name(ti.state)));
    parts.push(format!("ca_state={}", ca_state_name(ti.ca_state)));
    let opts = tcp_options(ti.options);
    if !opts.is_empty() {
        parts.push(format!("opts={opts}"));
    }
    parts.push(format!("rtt_us={}", ti.rtt));
    parts.push(format!("rttvar_us={}", ti.rttvar));
    parts.push(format!("rto_us={}", ti.rto));
    parts.push(format!("ato_us={}", ti.ato));
    parts.push(format!("snd_cwnd={}", ti.snd_cwnd));
    parts.push(format!("snd_ssthresh={}", ti.snd_ssthresh));
    parts.push(format!("rcv_ssthresh={}", ti.rcv_ssthresh));
    parts.push(format!("snd_mss={}", ti.snd_mss));
    parts.push(format!("rcv_mss={}", ti.rcv_mss));
    parts.push(format!("advmss={}", ti.advmss));
    parts.push(format!("pmtu={}", ti.pmtu));
    parts.push(format!("snd_wscale={}", ti.wscale & 0x0f));
    parts.push(format!("rcv_wscale={}", ti.wscale >> 4));
    parts.push(format!("unacked={}", ti.unacked));
    parts.push(format!("sacked={}", ti.sacked));
    parts.push(format!("lost={}", ti.lost));
    parts.push(format!("retrans={}", ti.retrans));
    parts.push(format!("retransmits={}", ti.retransmits));
    parts.push(format!("total_retrans={}", ti.total_retrans));
    parts.push(format!("reordering={}", ti.reordering));
    parts.push(format!("probes={}", ti.probes));
    parts.push(format!("backoff={}", ti.backoff));
    parts.push(format!("rcv_rtt_us={}", ti.rcv_rtt));
    parts.push(format!("rcv_space={}", ti.rcv_space));
    parts.push(format!("last_data_sent_ms={}", ti.last_data_sent));
    parts.push(format!("last_data_recv_ms={}", ti.last_data_recv));
    parts.push(format!("last_ack_recv_ms={}", ti.last_ack_recv));
}

#[cfg(target_os = "linux")]
fn tcp_state_name(state: u8) -> &'static str {
    match state {
        1 => "established",
        2 => "syn-sent",
        3 => "syn-recv",
        4 => "fin-wait-1",
        5 => "fin-wait-2",
        6 => "time-wait",
        7 => "close",
        8 => "close-wait",
        9 => "last-ack",
        10 => "listen",
        11 => "closing",
        _ => "unknown",
    }
}

#[cfg(target_os = "linux")]
fn ca_state_name(state: u8) -> &'static str {
    match state {
        0 => "open",
        1 => "disorder",
        2 => "cwr",
        3 => "recovery",
        4 => "loss",
        _ => "unknown",
    }
}

/// Decode the `tcpi_options` bitfield (TCPI_OPT_* in linux/tcp.h).
#[cfg(target_os = "linux")]
fn tcp_options(options: u8) -> String {
    let mut out: Vec<&str> = Vec::new();
    if options & 0x01 != 0 {
        out.push("ts");
    }
    if options & 0x02 != 0 {
        out.push("sack");
    }
    if options & 0x04 != 0 {
        out.push("wscale");
    }
    if options & 0x08 != 0 {
        out.push("ecn");
    }
    if options & 0x10 != 0 {
        out.push("ecn-seen");
    }
    if options & 0x20 != 0 {
        out.push("syn-data");
    }
    out.join(",")
}
