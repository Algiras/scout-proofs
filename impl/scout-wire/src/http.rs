// SPDX-License-Identifier: Apache-2.0

//! A deliberately small blocking HTTP/1.1 server (one thread per connection,
//! `Connection: close`) and a client transport that tests can wrap.
use crate::Error;
use serde_json::Value;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const MAX_HEADER: usize = 16 * 1024;
const MAX_BODY: usize = 1 << 20;

pub struct Request {
    pub method: String,
    pub path: String,
    pub query: HashMap<String, String>,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn json(status: u16, v: &Value) -> Response {
        Response {
            status,
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: serde_json::to_vec(v).unwrap_or_default(),
        }
    }
    pub fn raw_json(status: u16, body: Vec<u8>) -> Response {
        Response { status, headers: vec![("Content-Type".into(), "application/json".into())], body }
    }
    pub fn text(status: u16, s: &str) -> Response {
        Response { status, headers: vec![("Content-Type".into(), "text/plain".into())], body: s.as_bytes().to_vec() }
    }
    pub fn redirect(url: &str) -> Response {
        Response { status: 302, headers: vec![("Location".into(), url.into())], body: vec![] }
    }
}

/// Returning `None` closes the connection without answering (fault injection).
pub type Handler = Arc<dyn Fn(Request) -> Option<Response> + Send + Sync>;

pub struct Server {
    pub addr: SocketAddr,
    stop: Arc<AtomicBool>,
}

impl Server {
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Server limits. A connection that exceeds `max_conns` is answered 503 and closed;
/// a request must arrive completely within `request_timeout`, and no single read may stall longer than `idle_timeout`.
#[derive(Clone, Copy)]
pub struct Limits {
    pub max_conns: usize,
    pub request_timeout: Duration,
    pub idle_timeout: Duration,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits { max_conns: 256, request_timeout: Duration::from_secs(30), idle_timeout: Duration::from_secs(10) }
    }
}

pub fn serve(addr: &str, handler: Handler) -> std::io::Result<Server> {
    serve_with(addr, handler, Limits::default())
}

pub fn serve_with(addr: &str, handler: Handler, limits: Limits) -> std::io::Result<Server> {
    let l = TcpListener::bind(addr)?;
    let addr = l.local_addr()?;
    let stop = Arc::new(AtomicBool::new(false));
    let s2 = stop.clone();
    let live = Arc::new(AtomicUsize::new(0));
    std::thread::spawn(move || {
        for conn in l.incoming() {
            if s2.load(Ordering::SeqCst) {
                break;
            }
            let mut c = match conn {
                Ok(c) => c,
                Err(_) => {
                    // Typically out of file descriptors: back off instead of spinning.
                    std::thread::sleep(Duration::from_millis(50));
                    continue;
                }
            };
            if live.fetch_add(1, Ordering::SeqCst) >= limits.max_conns {
                live.fetch_sub(1, Ordering::SeqCst);
                let _ = c.set_write_timeout(Some(Duration::from_secs(1)));
                let _ = write_response(&mut c, &Response::text(503, "busy"));
                continue;
            }
            let (h, live) = (handler.clone(), live.clone());
            std::thread::spawn(move || {
                let _ = handle(c, h, limits);
                live.fetch_sub(1, Ordering::SeqCst);
            });
        }
    });
    Ok(Server { addr, stop })
}

/// Reads with a deadline for the whole request on top of the per-read idle timeout.
struct Deadline {
    stream: TcpStream,
    end: Instant,
    idle: Duration,
}

impl Read for Deadline {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let left = self.end.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "request took too long"));
        }
        self.stream.set_read_timeout(Some(left.min(self.idle)))?;
        self.stream.read(buf)
    }
}

/// Control characters and non-ASCII escaped, for access logs.
pub fn log_safe(s: &str) -> String {
    s.chars().flat_map(|c| if c.is_ascii_graphic() { vec![c] } else { c.escape_default().collect() }).collect()
}

fn handle(mut c: TcpStream, h: Handler, limits: Limits) -> std::io::Result<()> {
    c.set_write_timeout(Some(Duration::from_secs(10)))?;
    let mut r =
        BufReader::new(Deadline { stream: c.try_clone()?, end: Instant::now() + limits.request_timeout, idle: limits.idle_timeout });
    let req = match read_request(&mut r) {
        Ok(Some(req)) => req,
        Ok(None) => return Ok(()),
        Err(e) => {
            if let Some(rej) = e.get_ref().and_then(|g| g.downcast_ref::<Rejection>()) {
                let _ = write_response(&mut c, &Response::text(rej.0, rej.1));
            } else if e.kind() == std::io::ErrorKind::TimedOut || e.kind() == std::io::ErrorKind::WouldBlock {
                let _ = write_response(&mut c, &Response::text(408, "request timeout"));
            }
            return Ok(());
        }
    };
    let Some(resp) = h(req) else { return Ok(()) };
    write_response(&mut c, &resp)
}

fn write_response(c: &mut TcpStream, resp: &Response) -> std::io::Result<()> {
    let reason = match resp.status {
        200 => "OK",
        302 => "Found",
        400 => "Bad Request",
        408 => "Request Timeout",
        413 => "Content Too Large",
        431 => "Request Header Fields Too Large",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        _ => "Status",
    };
    let mut out = format!("HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\n", resp.status, reason, resp.body.len());
    for (k, v) in &resp.headers {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str("\r\n");
    c.write_all(out.as_bytes())?;
    c.write_all(&resp.body)?;
    c.flush()
}

/// Why a request was refused; carried inside an `InvalidData` error.
#[derive(Debug)]
struct Rejection(u16, &'static str);

impl std::fmt::Display for Rejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.0, self.1)
    }
}
impl std::error::Error for Rejection {}

fn bad(status: u16, why: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, Rejection(status, why))
}

/// One newline-terminated head line, never reading past the head limit.
/// An empty string means end of input before any byte.
fn head_line<R: BufRead>(r: &mut R, used: usize) -> std::io::Result<String> {
    let mut buf = Vec::new();
    r.by_ref().take((MAX_HEADER - used) as u64 + 1).read_until(b'\n', &mut buf)?;
    if used + buf.len() > MAX_HEADER {
        return Err(bad(431, "request head too large"));
    }
    if !buf.is_empty() && buf.last() != Some(&b'\n') {
        return Err(bad(400, "truncated request head"));
    }
    String::from_utf8(buf).map_err(|_| bad(400, "request head is not UTF-8"))
}

fn content_length(v: &str) -> std::io::Result<usize> {
    if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad(400, "invalid Content-Length"));
    }
    v.parse().map_err(|_| bad(413, "body too large"))
}

/// `Ok(None)`: the peer sent nothing. Refusals are `InvalidData` errors that
/// carry the status to answer with; other errors are I/O failures.
pub fn read_request<R: BufRead>(r: &mut R) -> std::io::Result<Option<Request>> {
    let line = head_line(r, 0)?;
    if line.is_empty() {
        return Ok(None);
    }
    let mut parts = line.split_whitespace();
    let (Some(method), Some(target)) = (parts.next(), parts.next()) else { return Err(bad(400, "malformed request line")) };
    let (path, qs) = target.split_once('?').unwrap_or((target, ""));
    let mut headers = HashMap::new();
    let mut total = line.len();
    let mut len: Option<usize> = None;
    loop {
        let l = head_line(r, total)?;
        if l.is_empty() {
            return Err(bad(400, "truncated request head"));
        }
        total += l.len();
        let l = l.trim_end();
        if l.is_empty() {
            break;
        }
        if let Some((k, v)) = l.split_once(':') {
            let k = k.trim().to_ascii_lowercase();
            match k.as_str() {
                "transfer-encoding" => return Err(bad(501, "Transfer-Encoding is not supported")),
                "content-length" => {
                    let n = content_length(v.trim())?;
                    if len.is_some_and(|p| p != n) {
                        return Err(bad(400, "conflicting Content-Length"));
                    }
                    len = Some(n);
                }
                _ => {}
            }
            headers.insert(k, v.trim().to_string());
        }
    }
    let len = len.unwrap_or(0);
    if len > MAX_BODY {
        return Err(bad(413, "body too large"));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).map_err(|e| if e.kind() == std::io::ErrorKind::UnexpectedEof { bad(400, "short body") } else { e })?;
    Ok(Some(Request { method: method.into(), path: path.into(), query: parse_form(qs), headers, body }))
}

pub fn urlencode(s: &str) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            o.push(b as char);
        } else {
            o.push_str(&format!("%{b:02X}"));
        }
    }
    o
}

pub fn urldecode(s: &str) -> String {
    let b = s.as_bytes();
    let mut o = Vec::new();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => o.push(b' '),
            b'%' if i + 2 < b.len() => {
                let h = std::str::from_utf8(&b[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok());
                match h {
                    Some(v) => {
                        o.push(v);
                        i += 2;
                    }
                    None => o.push(b'%'),
                }
            }
            c => o.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&o).into_owned()
}

pub fn parse_form(s: &str) -> HashMap<String, String> {
    s.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (urldecode(k), urldecode(v))
        })
        .collect()
}

/// Client side. Tests wrap this to drop replies after the server acted.
pub trait Transport: Send + Sync {
    fn call(&self, method: &str, url: &str, headers: &[(&str, &str)], body: &[u8]) -> Result<(u16, Vec<u8>), Error>;
}

pub struct Ureq {
    pub redirects: u32,
}

impl Transport for Ureq {
    fn call(&self, method: &str, url: &str, headers: &[(&str, &str)], body: &[u8]) -> Result<(u16, Vec<u8>), Error> {
        let agent = ureq::AgentBuilder::new().timeout(Duration::from_secs(15)).redirects(self.redirects).build();
        let mut rq = agent.request(method, url);
        for (k, v) in headers {
            rq = rq.set(k, v);
        }
        let resp = match if method == "GET" { rq.call() } else { rq.send_bytes(body) } {
            Ok(r) => r,
            Err(ureq::Error::Status(_, r)) => r,
            Err(e) => return Err(Error(format!("transport: {e}"))),
        };
        let status = resp.status();
        let mut buf = Vec::new();
        resp.into_reader().take(MAX_BODY as u64).read_to_end(&mut buf).map_err(|e| Error(format!("transport: {e}")))?;
        Ok((status, buf))
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    #[kani::proof]
    #[kani::unwind(6)]
    fn urldecode_never_panics_up_to_4_bytes() {
        let b: [u8; 4] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= 4);
        if let Ok(s) = std::str::from_utf8(&b[..n]) {
            let _ = urldecode(s);
        }
    }
}
