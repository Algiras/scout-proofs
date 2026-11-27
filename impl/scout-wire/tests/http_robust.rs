// SPDX-License-Identifier: Apache-2.0

//! Generated and mutated requests against the HTTP parser and the real server.
//! Limits under test: head 16 KiB, body 1 MiB, 10 s per-read timeout.
mod support;

use scout_wire::http::{log_safe, parse_form, read_request, serve, serve_with, urldecode, urlencode, Handler, Limits, Response, Server};
use serde_json::json;
use std::io::{Cursor, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Once};
use std::time::{Duration, Instant};
use support::Rng;

const MAX_HEADER: usize = 16 * 1024;
const MAX_BODY: usize = 1 << 20;
const DIRECT_CASES: usize = 30_000;
/// Each case is one TCP connection; loopback ephemeral ports in TIME_WAIT bound how many fit in a minute.
const SOCKET_CASES: usize = 8_000;

#[derive(Debug, PartialEq)]
enum Verdict {
    Accept { method: String, path: String, body: Vec<u8> },
    Reject(&'static str),
}

/// What a strict reading of the request bytes allows: complete lines, one valid
/// Content-Length, no Transfer-Encoding, bounded head, complete body.
fn reference(raw: &[u8]) -> Verdict {
    let (mut pos, mut total) = (0usize, 0usize);
    let mut first: Option<(String, String)> = None;
    let mut lens: Vec<String> = vec![];
    let mut te = false;
    loop {
        let Some(nl) = raw[pos..].iter().position(|&b| b == b'\n') else { return Verdict::Reject("unterminated line") };
        let line = &raw[pos..pos + nl + 1];
        pos += nl + 1;
        total += line.len();
        if total > MAX_HEADER {
            return Verdict::Reject("head too large");
        }
        let Ok(text) = std::str::from_utf8(line) else { return Verdict::Reject("non-utf8 head") };
        let t = text.trim_end();
        if first.is_none() {
            let mut parts = t.split_whitespace();
            let (Some(m), Some(target)) = (parts.next(), parts.next()) else { return Verdict::Reject("request line") };
            first = Some((m.to_string(), target.split_once('?').map(|x| x.0).unwrap_or(target).to_string()));
            continue;
        }
        if t.is_empty() {
            break;
        }
        if let Some((k, v)) = t.split_once(':') {
            match k.trim().to_ascii_lowercase().as_str() {
                "content-length" => lens.push(v.trim().to_string()),
                "transfer-encoding" => te = true,
                _ => {}
            }
        }
    }
    if te {
        return Verdict::Reject("transfer-encoding");
    }
    let mut len = 0usize;
    for (i, v) in lens.iter().enumerate() {
        if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
            return Verdict::Reject("bad content-length");
        }
        let Ok(n) = v.parse::<usize>() else { return Verdict::Reject("content-length overflow") };
        if i > 0 && n != len {
            return Verdict::Reject("conflicting content-length");
        }
        len = n;
    }
    if len > MAX_BODY {
        return Verdict::Reject("body too large");
    }
    if raw.len() - pos < len {
        return Verdict::Reject("short body");
    }
    let (method, path) = first.unwrap_or_default();
    Verdict::Accept { method, path, body: raw[pos..pos + len].to_vec() }
}

fn clip(s: &str) -> String {
    s.chars().take(200).collect()
}

fn direct(raw: &[u8]) -> Verdict {
    match read_request(&mut Cursor::new(raw)) {
        Ok(Some(r)) => Verdict::Accept { method: r.method, path: r.path, body: r.body },
        Ok(None) | Err(_) => Verdict::Reject("parser"),
    }
}

fn base(rng: &mut Rng) -> Vec<u8> {
    match rng.below(4) {
        0 => b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n".to_vec(),
        1 => {
            let body = format!("{{\"k\":\"{}\"}}", rng.below(1_000_000));
            format!(
                "POST /v1/echo?a=b&c=%41 HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
            .into_bytes()
        }
        2 => {
            let mut s = String::from("GET /a/b?x=1&y=%zz HTTP/1.1\r\nHost: x\r\n");
            for i in 0..rng.below(40) {
                s.push_str(&format!("X-H{i}: v{}\r\n", rng.below(1000)));
            }
            s.push_str("\r\n");
            s.into_bytes()
        }
        _ => {
            let body = "x".repeat(rng.below(3000));
            format!("POST /p HTTP/1.1\r\ncontent-length: {}\r\nAuthorization: Bearer abc\r\n\r\n{body}", body.len()).into_bytes()
        }
    }
}

fn replace_cl(v: &[u8], value: &str) -> Vec<u8> {
    let s = String::from_utf8_lossy(v).into_owned();
    let lower = s.to_ascii_lowercase();
    match lower.find("content-length:") {
        Some(i) => {
            let end = s[i..].find("\r\n").map(|e| i + e).unwrap_or(s.len());
            format!("{}Content-Length: {value}{}", &s[..i], &s[end..]).into_bytes()
        }
        None => match s.find("\r\n") {
            Some(e) => format!("{}\r\nContent-Length: {value}{}", &s[..e], &s[e..]).into_bytes(),
            None => v.to_vec(),
        },
    }
}

fn insert_header(v: &[u8], line: &[u8]) -> Vec<u8> {
    match v.windows(2).position(|w| w == b"\r\n") {
        Some(e) => [&v[..e + 2], line, b"\r\n", &v[e + 2..]].concat(),
        None => v.to_vec(),
    }
}

const CLS: [&str; 17] = [
    "-1",
    "-0",
    "+5",
    "0x10",
    "1e3",
    "",
    "  7 ",
    "99999999999999999999",
    "18446744073709551615",
    "18446744073709551616",
    "1048577",
    "1048576",
    "5 5",
    "5,5",
    "\u{663}",
    "0",
    "00000000000000000005",
];

fn mutate(rng: &mut Rng, mut v: Vec<u8>) -> Vec<u8> {
    match rng.below(24) {
        0 => {
            let n = rng.below(v.len() + 1);
            v.truncate(n);
        }
        1 => {
            for _ in 0..1 + rng.below(4) {
                if !v.is_empty() {
                    let i = rng.below(v.len());
                    v[i] ^= 1 << rng.below(8);
                }
            }
        }
        2 => {
            let i = rng.below(v.len() + 1);
            let b = *rng.pick(&[0u8, 0xff, 0x80, 0xc3, b'\r', b'\n', b' ', b':', b'%', b'\t']);
            v.insert(i, b);
        }
        3 => v = replace_cl(&v, rng.pick(&CLS)),
        4 => v = insert_header(&v, format!("Content-Length: {}", rng.below(50)).as_bytes()),
        5 => {
            v = insert_header(&v, b"Transfer-Encoding: chunked");
            v.extend_from_slice(b"5\r\nhello\r\n0\r\n\r\n");
        }
        6 => v = String::from_utf8_lossy(&v).replace("\r\n", "\n").into_bytes(),
        7 => v = String::from_utf8_lossy(&v).replacen("\r\n", "\r", 1).into_bytes(),
        8 => {
            let pad = vec![b'a'; 1000 + rng.below(40_000)];
            let at = v.iter().position(|&b| b == b' ').map(|i| i + 2).unwrap_or(0).min(v.len());
            v.splice(at..at, pad);
        }
        9 => {
            let big = [b"X-Big: ".as_slice(), &vec![b'b'; 1000 + rng.below(40_000)]].concat();
            v = insert_header(&v, &big);
        }
        10 => {
            for i in 0..500 + rng.below(1500) {
                v = insert_header(&v, format!("A{i}: b").as_bytes());
            }
        }
        11 => {
            let n = v.len().saturating_sub(1 + rng.below(8));
            v.truncate(n);
        }
        12 => v.extend(rng.bytes_in(1, 40)),
        13 => {
            let mut w = base(rng);
            v.append(&mut w);
        }
        14 => v = String::from_utf8_lossy(&v).replacen("\r\n\r\n", "\r\n", 1).into_bytes(),
        15 => {
            if !v.is_empty() {
                let a = rng.below(v.len());
                let b = (a + rng.below(20)).min(v.len());
                v.drain(a..b);
            }
        }
        16 => v = rng.bytes_in(0, 2000),
        17 => v = insert_header(&v, b"NoColonHere"),
        18 => v = insert_header(&v, b"X-N\0ul: va\0lue"),
        19 => v = [b"GET /\xff\xfe HTTP/1.1\r\n".as_slice(), b"\r\n"].concat(),
        20 => v = String::from_utf8_lossy(&v).replacen(' ', " \t  ", 1).into_bytes(),
        21 => v.clear(),
        22 => v = [b"\r\n".as_slice(), &v].concat(),
        _ => v = insert_header(&v, b"Content-Length : 3"),
    }
    v
}

fn case(seed: u64, i: usize) -> Vec<u8> {
    let mut rng = Rng::new(seed ^ (i as u64).wrapping_mul(0xA24B_AED4_963E_E407));
    let mut v = base(&mut rng);
    for _ in 0..rng.below(4) {
        v = mutate(&mut rng, v);
    }
    v
}

#[test]
fn parser_matches_strict_reference_on_generated_requests() {
    let mut bad = vec![];
    let (mut accepted, mut rejected) = (0, 0);
    for i in 0..DIRECT_CASES {
        let raw = case(1, i);
        let (want, got) = (reference(&raw), direct(&raw));
        match (&want, &got) {
            (Verdict::Accept { .. }, Verdict::Accept { .. }) if want == got => accepted += 1,
            (Verdict::Reject(_), Verdict::Reject(_)) => rejected += 1,
            _ => {
                if bad.len() < 12 {
                    bad.push(format!(
                        "case {i}: reference {} parser {} input {:?}",
                        clip(&format!("{want:?}")),
                        clip(&format!("{got:?}")),
                        String::from_utf8_lossy(&raw[..raw.len().min(160)])
                    ));
                }
            }
        }
    }
    println!("parser cases {DIRECT_CASES}: accepted {accepted}, rejected {rejected}");
    assert!(bad.is_empty(), "{} disagreements, first ones:\n{}", DIRECT_CASES - accepted - rejected, bad.join("\n"));
}

static PANICS: AtomicUsize = AtomicUsize::new(0);

fn count_panics() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |i| {
            if std::thread::current().name().is_none() {
                PANICS.fetch_add(1, Ordering::SeqCst);
            }
            prev(i);
        }));
    });
}

fn fnv(b: &[u8]) -> u64 {
    b.iter().fold(0xcbf2_9ce4_8422_2325u64, |h, &x| (h ^ x as u64).wrapping_mul(0x100_0000_01b3))
}

fn echo_server() -> Server {
    count_panics();
    let h: Handler = Arc::new(|r| {
        Some(Response::json(200, &json!({ "m": r.method, "p": r.path, "len": r.body.len(), "sum": fnv(&r.body).to_string() })))
    });
    serve("127.0.0.1:0", h).unwrap()
}

enum Reply {
    Closed,
    Status(u16, Vec<u8>),
}

fn exchange(addr: SocketAddr, raw: &[u8], slow: bool) -> Result<Reply, String> {
    let mut tries = 0;
    let mut s = loop {
        match TcpStream::connect(addr) {
            Ok(s) => break s,
            Err(e) if tries < 100 => {
                tries += 1;
                let _ = e;
                std::thread::sleep(Duration::from_millis(250));
            }
            Err(e) => return Err(format!("connect: {e}")),
        }
    };
    s.set_read_timeout(Some(Duration::from_secs(5))).ok();
    s.set_write_timeout(Some(Duration::from_secs(5))).ok();
    if slow {
        for chunk in raw.chunks(raw.len().div_ceil(3).max(1)) {
            if s.write_all(chunk).is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(3));
        }
    } else {
        let _ = s.write_all(raw);
    }
    let _ = s.shutdown(Shutdown::Write);
    let mut out = vec![];
    if let Err(e) = s.read_to_end(&mut out) {
        if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) {
            return Err("server did not finish within 5 s".into());
        }
    }
    if out.is_empty() {
        return Ok(Reply::Closed);
    }
    let head_end = out.windows(4).position(|w| w == b"\r\n\r\n").ok_or("response without head")?;
    let head = String::from_utf8_lossy(&out[..head_end]).into_owned();
    let status =
        head.strip_prefix("HTTP/1.1 ").and_then(|r| r.get(..3)).and_then(|c| c.parse().ok()).ok_or(format!("bad status line {head:?}"))?;
    Ok(Reply::Status(status, out[head_end + 4..].to_vec()))
}

fn check_socket_case(addr: SocketAddr, i: usize, raw: &[u8]) -> Option<String> {
    let want = reference(raw);
    let got = match exchange(addr, raw, i.is_multiple_of(40)) {
        Ok(g) => g,
        Err(e) => return Some(format!("case {i}: {e}")),
    };
    let ctx = || String::from_utf8_lossy(&raw[..raw.len().min(160)]).into_owned();
    match (want, got) {
        (Verdict::Accept { method, path, body }, Reply::Status(200, b)) => {
            let v: serde_json::Value = serde_json::from_slice(&b).ok()?;
            let ok = v["m"] == method.as_str()
                && v["p"] == path.as_str()
                && v["len"] == body.len()
                && v["sum"] == fnv(&body).to_string().as_str();
            (!ok).then(|| format!("case {i}: handler saw different request than the reference {v} input {:?}", ctx()))
        }
        (Verdict::Accept { .. }, _) => Some(format!("case {i}: valid request not answered, input {:?}", ctx())),
        (Verdict::Reject(_), Reply::Closed) => None,
        (Verdict::Reject(_), Reply::Status(s, _)) if s >= 400 => None,
        (Verdict::Reject(why), Reply::Status(s, _)) => Some(format!("case {i}: {why} request got {s}, input {:?}", ctx())),
    }
}

#[test]
fn server_survives_generated_requests_over_sockets() {
    let srv = echo_server();
    let addr = srv.addr;
    let next = Arc::new(AtomicUsize::new(0));
    let started = Instant::now();
    let workers: Vec<_> = (0..8)
        .map(|_| {
            let next = next.clone();
            std::thread::spawn(move || {
                let mut bad = vec![];
                loop {
                    let i = next.fetch_add(1, Ordering::SeqCst);
                    if i >= SOCKET_CASES {
                        return bad;
                    }
                    if let Some(f) = check_socket_case(addr, i, &case(2, i)) {
                        bad.push(f);
                    }
                }
            })
        })
        .collect();
    let bad: Vec<String> = workers.into_iter().flat_map(|w| w.join().unwrap()).collect();
    println!("socket cases {SOCKET_CASES} in {:.1}s, failures {}", started.elapsed().as_secs_f64(), bad.len());
    match exchange(addr, b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n", false) {
        Ok(Reply::Status(200, _)) => {}
        _ => panic!("server stopped serving valid requests"),
    }
    assert_eq!(PANICS.load(Ordering::SeqCst), 0, "a server thread panicked");
    assert!(bad.is_empty(), "{} failures, first ones:\n{}", bad.len(), bad[..bad.len().min(12)].join("\n"));
}

#[test]
fn limits_at_the_boundary() {
    let srv = echo_server();
    let at = |len: usize| {
        let body = vec![b'a'; len];
        let mut raw = format!("POST /p HTTP/1.1\r\nContent-Length: {len}\r\n\r\n").into_bytes();
        raw.extend(body);
        exchange(srv.addr, &raw, false).unwrap()
    };
    assert!(matches!(at(MAX_BODY), Reply::Status(200, _)));
    assert!(matches!(at(MAX_BODY + 1), Reply::Closed | Reply::Status(400..=599, _)));
    let line = |pad: usize| {
        let mut raw = b"GET /".to_vec();
        raw.extend(std::iter::repeat_n(b'a', pad));
        raw.extend_from_slice(b" HTTP/1.1\r\n\r\n");
        exchange(srv.addr, &raw, false).unwrap()
    };
    assert!(matches!(line(MAX_HEADER - 64), Reply::Status(200, _)));
    assert!(matches!(line(MAX_HEADER + 100), Reply::Closed | Reply::Status(400..=599, _)));
}

/// A request line without any newline must not be buffered without bound: the server answers 431 after the head limit.
#[test]
fn endless_request_line_is_cut_off() {
    let srv = echo_server();
    let mut s = TcpStream::connect(srv.addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    let chunk = vec![b'a'; 8 * 1024];
    let mut sent = 0usize;
    while sent < 4 * MAX_HEADER {
        match s.write(&chunk) {
            Ok(n) => sent += n,
            Err(_) => break,
        }
    }
    let mut out = vec![0u8; 64];
    let n = s.read(&mut out).unwrap_or(0);
    assert!(
        out[..n].starts_with(b"HTTP/1.1 431"),
        "no 431 after {sent} bytes of one unterminated line: {:?}",
        String::from_utf8_lossy(&out[..n])
    );
}

fn limited_server(l: Limits) -> Server {
    let h: Handler = Arc::new(|_| Some(Response::text(200, "ok")));
    serve_with("127.0.0.1:0", h, l).unwrap()
}

#[test]
fn connections_beyond_the_cap_are_refused_and_slots_are_freed() {
    let srv = limited_server(Limits { max_conns: 20, ..Limits::default() });
    let idle: Vec<TcpStream> = (0..20).map(|_| TcpStream::connect(srv.addr).unwrap()).collect();
    std::thread::sleep(Duration::from_millis(300));
    let t = Instant::now();
    match exchange(srv.addr, b"GET /healthz HTTP/1.1\r\n\r\n", false) {
        Ok(Reply::Status(503, _)) => {}
        _ => panic!("the 21st connection was not refused with 503"),
    }
    assert!(t.elapsed() < Duration::from_secs(2), "refusal must be immediate");
    drop(idle);
    let mut served = false;
    for _ in 0..40 {
        if matches!(exchange(srv.addr, b"GET /healthz HTTP/1.1\r\n\r\n", false), Ok(Reply::Status(200, _))) {
            served = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(served, "slots were not freed after the idle connections closed");
}

#[test]
fn slow_drip_is_cut_off_by_the_request_deadline() {
    let srv = limited_server(Limits { max_conns: 16, request_timeout: Duration::from_secs(3), idle_timeout: Duration::from_secs(1) });
    let mut s = TcpStream::connect(srv.addr).unwrap();
    let start = Instant::now();
    let mut alive = true;
    for b in b"GET /healthz HTTP/1.1\r\nHost: x\r\nX-A: a\r\nX-B: b\r\n".iter() {
        std::thread::sleep(Duration::from_millis(400));
        if s.write_all(&[*b]).is_err() {
            alive = false;
            break;
        }
        if start.elapsed() > Duration::from_secs(8) {
            break;
        }
    }
    let mut out = vec![];
    s.set_read_timeout(Some(Duration::from_secs(5))).ok();
    let _ = s.read_to_end(&mut out);
    println!("slow drip: write failed {}, ended after {:.1}s", !alive, start.elapsed().as_secs_f64());
    assert!(start.elapsed() < Duration::from_secs(7), "a one-byte-per-400ms client held the connection for {:?}", start.elapsed());
}

#[test]
fn stalled_head_is_closed_by_the_read_timeout() {
    let srv = echo_server();
    let mut s = TcpStream::connect(srv.addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
    s.write_all(b"GET /heal").unwrap();
    let t = Instant::now();
    let mut out = vec![];
    let _ = s.read_to_end(&mut out);
    let waited = t.elapsed();
    println!("stalled head closed after {:.1}s", waited.as_secs_f64());
    assert!(waited < Duration::from_secs(14), "server never closed a stalled connection");
}

#[test]
fn url_helpers_roundtrip_and_never_panic() {
    let mut rng = Rng::new(7);
    for _ in 0..20_000 {
        let n = rng.below(40);
        let s: String = (0..n)
            .map(|_| char::from_u32(*rng.pick(&[0x20u32, 0x25, 0x26, 0x2b, 0x3d, 0x41, 0x7e, 0xe9, 0x4e2d, 0x1f600, 0x0])).unwrap())
            .collect();
        assert_eq!(urldecode(&urlencode(&s)), s);
        let raw = String::from_utf8_lossy(&rng.bytes_in(0, 60)).into_owned();
        let _ = urldecode(&raw);
        let _ = parse_form(&raw);
        let _ = parse_form(&format!("{raw}&{}={}", urlencode(&s), urlencode(&raw)));
    }
    assert_eq!(urldecode("%"), "%");
    assert_eq!(urldecode("%4"), "%4");
    assert_eq!(urldecode("%41"), "A");
    assert_eq!(urldecode("a+b%2"), "a b%2");
    assert_eq!(parse_form("a=1&a=2&b").get("a").map(String::as_str), Some("2"));
}

#[test]
fn log_safe_escapes_control_characters() {
    let s = log_safe("/a\x1b[31m\r\n\0\u{7f}\u{e9}b");
    assert!(s.bytes().all(|b| b.is_ascii_graphic()), "{s:?}");
    assert_eq!(log_safe("/v1/sessions/abc/renew"), "/v1/sessions/abc/renew");
}
