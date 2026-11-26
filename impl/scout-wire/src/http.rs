// SPDX-License-Identifier: CC-BY-4.0

//! A deliberately small blocking HTTP/1.1 server (one thread per connection,
//! `Connection: close`) and a client transport that tests can wrap.
use crate::Error;
use serde_json::Value;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

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

pub fn serve(addr: &str, handler: Handler) -> std::io::Result<Server> {
    let l = TcpListener::bind(addr)?;
    let addr = l.local_addr()?;
    let stop = Arc::new(AtomicBool::new(false));
    let s2 = stop.clone();
    std::thread::spawn(move || {
        for conn in l.incoming() {
            if s2.load(Ordering::SeqCst) {
                break;
            }
            if let Ok(c) = conn {
                let h = handler.clone();
                std::thread::spawn(move || {
                    let _ = handle(c, h);
                });
            }
        }
    });
    Ok(Server { addr, stop })
}

fn handle(mut c: TcpStream, h: Handler) -> std::io::Result<()> {
    c.set_read_timeout(Some(Duration::from_secs(10)))?;
    c.set_write_timeout(Some(Duration::from_secs(10)))?;
    let mut r = BufReader::new(c.try_clone()?);
    let Some(req) = read_request(&mut r)? else { return Ok(()) };
    let Some(resp) = h(req) else { return Ok(()) };
    let reason = match resp.status {
        200 => "OK",
        302 => "Found",
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

fn read_request(r: &mut BufReader<TcpStream>) -> std::io::Result<Option<Request>> {
    let mut line = String::new();
    if r.read_line(&mut line)? == 0 {
        return Ok(None);
    }
    let mut parts = line.split_whitespace();
    let (Some(method), Some(target)) = (parts.next(), parts.next()) else { return Ok(None) };
    let (path, qs) = target.split_once('?').unwrap_or((target, ""));
    let mut headers = HashMap::new();
    let mut total = line.len();
    loop {
        let mut l = String::new();
        r.read_line(&mut l)?;
        total += l.len();
        if total > MAX_HEADER {
            return Ok(None);
        }
        let l = l.trim_end();
        if l.is_empty() {
            break;
        }
        if let Some((k, v)) = l.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    let len: usize = headers.get("content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
    if len > MAX_BODY {
        return Ok(None);
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
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
