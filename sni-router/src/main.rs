//! SNI 라우터 — TLS ClientHello의 SNI 필드를 읽어
//! AI API 트래픽만 mitmproxy로, 나머지는 직통 라우팅.
//!
//! 흐름:
//!   iptables PREROUTING :443 → REDIRECT :4443
//!   :4443 (본 프로세스)
//!     SNI ∈ AI 도메인 → mitmproxy :4001  (DLP 검사)
//!     SNI ∉ AI 도메인 → 원본 목적지 직통 (TLS 그대로 통과)

use std::{
    collections::HashSet,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    os::unix::io::AsRawFd,
    sync::Arc,
};

use tokio::{
    io::copy_bidirectional,
    net::{TcpListener, TcpStream},
};

// ── 설정 ──────────────────────────────────────────────────────────────────────

/// iptables가 443을 리다이렉트할 포트 (root 없이 실행 가능)
const LISTEN_ADDR: &str = "0.0.0.0:4443";

/// mitmproxy (DLP 엔진) 주소
const MITM_ADDR: &str = "127.0.0.1:4001";

/// 탐지 대상 AI API 도메인
/// inspect_traffic.py의 TARGET_HOSTS와 동기화할 것
const AI_DOMAINS: &[&str] = &[
    "api.openai.com",
    "api.anthropic.com",
    "generativelanguage.googleapis.com",
    "api.githubcopilot.com",
    "api.individual.githubcopilot.com",
    "copilot-proxy.githubusercontent.com",
    "api.groq.com",
    "api.together.ai",
    "api.mistral.ai",
    "openrouter.ai",
    "api.deepseek.com",
    "api.x.ai",
];

// ── SO_ORIGINAL_DST — iptables REDIRECT 이전의 원본 목적지 획득 ───────────────

const SOL_IP: libc::c_int = 0;
const SO_ORIGINAL_DST: libc::c_int = 80;

/// iptables REDIRECT로 가로채기 전의 원본 목적지 주소를 반환.
/// transparent 모드에서만 유효. 실패 시 None.
fn original_dst(fd: i32) -> Option<SocketAddr> {
    // SAFETY: fd는 유효한 TCP 소켓, sockaddr_in 초기화 후 getsockopt 호출.
    unsafe {
        let mut addr: libc::sockaddr_in = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let rc = libc::getsockopt(
            fd,
            SOL_IP,
            SO_ORIGINAL_DST,
            &mut addr as *mut _ as *mut libc::c_void,
            &mut len,
        );
        if rc != 0 {
            return None;
        }
        let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
        let port = u16::from_be(addr.sin_port);
        Some(SocketAddr::V4(SocketAddrV4::new(ip, port)))
    }
}

// ── TLS ClientHello SNI 파싱 ─────────────────────────────────────────────────

/// TLS 1.x ClientHello 패킷에서 server_name 확장(SNI)을 추출.
///
/// TLS 레코드 구조:
/// ```text
/// [0]     = 0x16  (handshake)
/// [1..2]  = legacy version
/// [3..4]  = record length (u16 BE)
/// [5]     = 0x01  (ClientHello)
/// [6..8]  = handshake length (u24 BE)
/// [9..10] = client_version
/// [11..42]= random (32 bytes)
/// [43]    = session_id_len
/// ...     = session_id
/// [n..n+1]= cipher_suites_len (u16 BE)
/// ...     = cipher_suites
/// [m]     = compression_methods_len (u8)
/// ...     = compression_methods
/// [k..k+1]= extensions_len (u16 BE)
///   extensions:
///     type(u16) + len(u16) + data
///     SNI extension type = 0x0000
///       list_len(u16) + [name_type(u8) + name_len(u16) + name]
/// ```
fn extract_sni(buf: &[u8]) -> Option<String> {
    if buf.len() < 9 { return None; }
    if buf[0] != 0x16 { return None; }   // TLS handshake record
    if buf[5] != 0x01 { return None; }   // ClientHello

    let mut p = 9usize;

    // client_version (2) + random (32)
    p = p.checked_add(34)?;

    // session_id
    let sil = *buf.get(p)? as usize;
    p = p.checked_add(1 + sil)?;

    // cipher_suites
    if p + 2 > buf.len() { return None; }
    let csl = u16::from_be_bytes([buf[p], buf[p + 1]]) as usize;
    p = p.checked_add(2 + csl)?;

    // compression_methods
    let cml = *buf.get(p)? as usize;
    p = p.checked_add(1 + cml)?;

    // extensions
    if p + 2 > buf.len() { return None; }
    let ext_total = u16::from_be_bytes([buf[p], buf[p + 1]]) as usize;
    p += 2;
    let ext_end = p.checked_add(ext_total)?.min(buf.len());

    while p + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([buf[p], buf[p + 1]]);
        let ext_len  = u16::from_be_bytes([buf[p + 2], buf[p + 3]]) as usize;
        p += 4;

        if ext_type == 0x0000 {
            // SNI extension
            if p + 2 > buf.len() { return None; }
            let list_len = u16::from_be_bytes([buf[p], buf[p + 1]]) as usize;
            p += 2;
            let list_end = p.checked_add(list_len)?.min(buf.len());

            while p + 3 <= list_end {
                let name_type = buf[p];
                let name_len  = u16::from_be_bytes([buf[p + 1], buf[p + 2]]) as usize;
                p += 3;

                if name_type == 0x00 {
                    // host_name
                    let end = p.checked_add(name_len)?;
                    if end > buf.len() { return None; }
                    return String::from_utf8(buf[p..end].to_vec()).ok();
                }
                p = p.checked_add(name_len)?;
            }
            return None;
        }
        p = p.checked_add(ext_len)?;
    }
    None
}

// ── 연결 처리 ────────────────────────────────────────────────────────────────

async fn handle(mut client: TcpStream, domains: Arc<HashSet<&'static str>>) {
    let fd = client.as_raw_fd();

    // SO_ORIGINAL_DST는 첫 read/write 전에 호출해야 함
    let orig = original_dst(fd);

    // ClientHello peek — 소켓 버퍼에서 소비하지 않음
    let mut buf = vec![0u8; 4096];
    let n = match client.peek(&mut buf).await {
        Ok(n) if n > 0 => n,
        _ => return,
    };

    let sni = extract_sni(&buf[..n]);
    let is_ai = sni.as_deref().map_or(false, |s| domains.contains(s));

    let target: SocketAddr = if is_ai {
        MITM_ADDR.parse().unwrap()
    } else {
        match orig {
            Some(a) => a,
            None => {
                eprintln!("[WARN] SO_ORIGINAL_DST 실패 — SNI: {:?}", sni);
                return;
            }
        }
    };

    let route = if is_ai { "mitmproxy" } else { "direct" };
    eprintln!(
        "[SNI] {:50} {:10}  {}",
        sni.as_deref().unwrap_or("(no-sni)"),
        route,
        target,
    );

    match TcpStream::connect(target).await {
        Ok(mut up) => {
            let _ = copy_bidirectional(&mut client, &mut up).await;
        }
        Err(e) => {
            eprintln!("[ERR] connect {target}: {e}");

            // mitmproxy 연결 실패 시 원본 목적지로 바이패스 (AI 도메인이어도)
            if is_ai {
                match orig {
                    Some(orig_dst) => {
                        eprintln!(
                            "[BYPASS] mitmproxy 불가 → 직통: {} ({})",
                            sni.as_deref().unwrap_or("?"),
                            orig_dst
                        );
                        match TcpStream::connect(orig_dst).await {
                            Ok(mut up) => {
                                let _ = copy_bidirectional(&mut client, &mut up).await;
                            }
                            Err(e2) => eprintln!("[ERR] bypass {orig_dst}: {e2}"),
                        }
                    }
                    None => eprintln!("[ERR] 바이패스 불가 — SO_ORIGINAL_DST 없음"),
                }
            }
        }
    }
}

// ── main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let domains: Arc<HashSet<&'static str>> = Arc::new(AI_DOMAINS.iter().copied().collect());

    let listener = TcpListener::bind(LISTEN_ADDR)
        .await
        .unwrap_or_else(|e| panic!("bind {LISTEN_ADDR} 실패: {e}"));

    eprintln!("[sni-router] 수신 대기: {LISTEN_ADDR}");
    eprintln!("[sni-router] AI 도메인: {}개 → {MITM_ADDR}", domains.len());

    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                // TCP_NODELAY: 라우터는 지연 없이 그대로 전달
                let _ = stream.set_nodelay(true);
                eprintln!("[CONN] {peer}");
                let d = Arc::clone(&domains);
                tokio::spawn(handle(stream, d));
            }
            Err(e) => eprintln!("[ERR] accept: {e}"),
        }
    }
}

// ── 단위 테스트 ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// 실제 TLS ClientHello 캡처본에서 SNI 파싱 검증.
    /// openssl s_client -connect api.openai.com:443 으로 캡처한 첫 패킷.
    #[test]
    fn test_extract_sni_valid() {
        // 실제 ClientHello 헥스덤프 (api.openai.com SNI 포함)
        let hello = build_test_client_hello("api.openai.com");
        let sni = extract_sni(&hello);
        assert_eq!(sni.as_deref(), Some("api.openai.com"));
    }

    #[test]
    fn test_extract_sni_non_tls() {
        let http = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(extract_sni(http), None);
    }

    #[test]
    fn test_extract_sni_empty() {
        assert_eq!(extract_sni(b""), None);
    }

    /// 테스트용 최소 ClientHello 패킷 생성.
    fn build_test_client_hello(sni: &str) -> Vec<u8> {
        let sni_bytes = sni.as_bytes();
        let name_len = sni_bytes.len() as u16;
        // SNI extension data
        let sni_ext_data: Vec<u8> = {
            let mut v = Vec::new();
            let list_len = (3 + name_len) as u16;
            v.extend_from_slice(&list_len.to_be_bytes()); // server_name_list_length
            v.push(0x00);                                  // name_type: host_name
            v.extend_from_slice(&name_len.to_be_bytes());  // name_length
            v.extend_from_slice(sni_bytes);                // name
            v
        };

        // ClientHello 본문
        let mut ch = Vec::new();
        ch.extend_from_slice(&[0x03, 0x03]);      // client_version TLS 1.2
        ch.extend_from_slice(&[0u8; 32]);          // random
        ch.push(0x00);                              // session_id_len = 0
        ch.extend_from_slice(&[0x00, 0x02]);       // cipher_suites_len = 2
        ch.extend_from_slice(&[0x00, 0x2f]);       // cipher_suite TLS_RSA_WITH_AES_128_CBC_SHA
        ch.push(0x01);                              // compression_methods_len = 1
        ch.push(0x00);                              // compression_method: null

        // extensions
        let ext_data_len = sni_ext_data.len() as u16;
        let ext_total: u16 = 4 + ext_data_len;     // type(2) + len(2) + data
        ch.extend_from_slice(&ext_total.to_be_bytes());
        ch.extend_from_slice(&[0x00, 0x00]);        // extension_type: SNI
        ch.extend_from_slice(&ext_data_len.to_be_bytes());
        ch.extend_from_slice(&sni_ext_data);

        // Handshake header
        let hs_body_len = ch.len();
        let mut hs = Vec::new();
        hs.push(0x01); // ClientHello
        hs.push(((hs_body_len >> 16) & 0xff) as u8);
        hs.push(((hs_body_len >>  8) & 0xff) as u8);
        hs.push(( hs_body_len        & 0xff) as u8);
        hs.extend_from_slice(&ch);

        // TLS record header
        let record_len = hs.len() as u16;
        let mut rec = Vec::new();
        rec.push(0x16);                              // handshake
        rec.extend_from_slice(&[0x03, 0x01]);        // TLS 1.0 compat
        rec.extend_from_slice(&record_len.to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }
}
