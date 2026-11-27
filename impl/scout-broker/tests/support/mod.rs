// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]

use scout_broker::provider::Provider;
use scout_broker::renewal::Renewer;
use scout_broker::server::{Broker, Config};
use scout_broker::store::MemStore;
use scout_mockprovider::Config as PConfig;
use scout_runner::{Client, Grant};
use scout_wire::http::{serve, Handler, Server, Transport, Ureq};
use scout_wire::now_secs;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Once, OnceLock};
use std::time::{Duration, Instant};

pub const CLIENT_SECRET: &str = "client-secret-xyz";
pub const COMMIT_KEY: &[u8] = b"commit-key-0123456789abcdef";

pub struct Stack {
    pub prov: Server,
    inner: Option<(Server, Arc<Broker>, Arc<MemStore>)>,
    pub path: Option<PathBuf>,
    transport: Arc<dyn Transport>,
}

pub fn start_broker(prov_url: &str, store: Arc<MemStore>, transport: Arc<dyn Transport>) -> (Server, Arc<Broker>) {
    let cell: Arc<OnceLock<Arc<Broker>>> = Arc::new(OnceLock::new());
    let c2 = cell.clone();
    let h: Handler = Arc::new(move |r| c2.get().and_then(|b| b.handler()(r)));
    let srv = serve("127.0.0.1:0", h).unwrap();
    let base = srv.url();
    let provider = Provider {
        auth_url: format!("{prov_url}/authorize"),
        token_url: format!("{prov_url}/token"),
        revoke_url: Some(format!("{prov_url}/revoke")),
        client_id: "scout-demo".into(),
        client_secret: CLIENT_SECRET.into(),
        scope: "read".into(),
        transport,
    };
    let renewer = Renewer::new(store.clone(), COMMIT_KEY.to_vec(), "scout-demo", Arc::new(now_secs));
    let cfg = Config { authority: base.trim_start_matches("http://").to_string(), public_base: base, default_ttl: 3600, max_ttl: 86400 };
    let broker = Arc::new(Broker { cfg, store, renewer, provider });
    cell.set(broker.clone()).ok();
    (srv, broker)
}

pub fn ureq() -> Arc<dyn Transport> {
    Arc::new(Ureq { redirects: 0 })
}

impl Stack {
    pub fn new() -> Stack {
        Stack::build(3600, Arc::new(MemStore::new()), None, ureq())
    }

    pub fn with_file(access_ttl: u64, path: &Path) -> Stack {
        Stack::build(access_ttl, Arc::new(MemStore::open_file(path).unwrap()), Some(path.to_path_buf()), ureq())
    }

    pub fn with_access_ttl(access_ttl: u64) -> Stack {
        Stack::build(access_ttl, Arc::new(MemStore::new()), None, ureq())
    }

    pub fn with_transport(t: Arc<dyn Transport>) -> Stack {
        Stack::build(3600, Arc::new(MemStore::new()), None, t)
    }

    fn build(access_ttl: u64, store: Arc<MemStore>, path: Option<PathBuf>, transport: Arc<dyn Transport>) -> Stack {
        let prov = scout_mockprovider::start(
            "127.0.0.1:0",
            PConfig { client_id: "scout-demo".into(), client_secret: CLIENT_SECRET.into(), auto_approve: true, access_ttl },
        )
        .unwrap();
        let (srv, broker) = start_broker(&prov.url(), store.clone(), transport.clone());
        Stack { prov, inner: Some((srv, broker, store)), path, transport }
    }

    /// Kills the broker (server, in-memory state, file lock) and starts a new one over the same file and provider.
    pub fn restart(&mut self) {
        let path = self.path.clone().expect("file store");
        if let Some((srv, _, _)) = self.inner.take() {
            srv.stop();
        }
        let store = (0..200)
            .find_map(|_| {
                MemStore::open_file(&path).ok().or_else(|| {
                    std::thread::sleep(Duration::from_millis(25));
                    None
                })
            })
            .expect("the store file was not released");
        let store = Arc::new(store);
        let (srv, broker) = start_broker(&self.prov.url(), store.clone(), self.transport.clone());
        self.inner = Some((srv, broker, store));
    }

    pub fn srv(&self) -> &Server {
        &self.inner.as_ref().unwrap().0
    }

    pub fn broker(&self) -> &Arc<Broker> {
        &self.inner.as_ref().unwrap().1
    }

    pub fn store(&self) -> &Arc<MemStore> {
        &self.inner.as_ref().unwrap().2
    }

    pub fn url(&self) -> String {
        self.srv().url()
    }

    pub fn stats(&self) -> Value {
        get(&format!("{}/debug/stats", self.prov.url()), None).1
    }

    pub fn family_calls(&self) -> Vec<u64> {
        self.stats()["families"].as_array().unwrap().iter().map(|f| f["refreshCalls"].as_u64().unwrap()).collect()
    }

    pub fn revocations(&self) -> u64 {
        self.stats()["revocations"].as_u64().unwrap()
    }

    pub fn whoami(&self, tok: &str) -> u16 {
        get(&format!("{}/api/whoami", self.prov.url()), Some(tok)).0
    }

    pub fn onboard(&self) -> (Client, Grant) {
        self.onboard_with(ureq())
    }

    pub fn onboard_with(&self, tr: Arc<dyn Transport>) -> (Client, Grant) {
        let mut c = Client::new(&self.url(), tr);
        c.create(3600).unwrap();
        let (s, _) = (Ureq { redirects: 5 }).call("GET", &c.consent_url("alice"), &[], &[]).unwrap();
        assert_eq!(s, 200);
        let g = c.fetch_grant().unwrap();
        (c, g)
    }

    pub fn repoint(&self, c: &mut Client) {
        c.base = self.url();
        c.authority = self.url().trim_start_matches("http://").to_string();
    }
}

pub fn get(url: &str, bearer: Option<&str>) -> (u16, Value) {
    let auth = bearer.map(|b| format!("Bearer {b}")).unwrap_or_default();
    let hdr: Vec<(&str, &str)> = if bearer.is_some() { vec![("Authorization", auth.as_str())] } else { vec![] };
    let (s, b) = (Ureq { redirects: 0 }).call("GET", url, &hdr, &[]).unwrap();
    (s, serde_json::from_slice(&b).unwrap_or(Value::Null))
}

pub fn post_bytes(url: &str, body: &[u8]) -> Result<(u16, Vec<u8>), scout_wire::Error> {
    (Ureq { redirects: 0 }).call("POST", url, &[("Content-Type", "application/json")], body)
}

pub fn post(url: &str, body: &Value) -> (u16, Value) {
    let (s, b) = post_bytes(url, &serde_json::to_vec(body).unwrap()).unwrap();
    (s, serde_json::from_slice(&b).unwrap_or(Value::Null))
}

pub fn temp_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("scout-{tag}-{}", scout_wire::random_id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Wraps a transport: runs a hook once after the first call whose URL ends with the given suffix.
pub struct Hook {
    pub suffix: &'static str,
    pub hook: std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl Transport for Hook {
    fn call(&self, m: &str, url: &str, h: &[(&str, &str)], b: &[u8]) -> Result<(u16, Vec<u8>), scout_wire::Error> {
        let r = (Ureq { redirects: 0 }).call(m, url, h, b)?;
        if url.ends_with(self.suffix) {
            if let Some(f) = self.hook.lock().unwrap().take() {
                f();
            }
        }
        Ok(r)
    }
}

// ---- child processes ----

pub fn bin_dir() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    exe.parent().and_then(Path::parent).unwrap().to_path_buf()
}

pub fn bin(name: &str) -> PathBuf {
    static BUILT: Once = Once::new();
    BUILT.call_once(|| {
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
        let mut cmd = Command::new(cargo);
        cmd.args(["build", "--locked", "-p", "scout-runner", "-p", "scout-mockprovider", "-p", "scout-broker", "-p", "scout-attacker"]);
        if bin_dir().file_name().is_some_and(|n| n == "release") {
            cmd.arg("--release");
        }
        let ok = cmd.status().map(|s| s.success()).unwrap_or(false);
        assert!(ok, "building the workspace binaries failed");
    });
    bin_dir().join(name)
}

pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

pub struct Proc {
    pub child: Child,
    pub out: PathBuf,
    pub err: PathBuf,
}

impl Proc {
    pub fn spawn(dir: &Path, tag: &str, bin_name: &str, args: &[&str], env: &[(&str, &str)]) -> Proc {
        let (out, err) = (dir.join(format!("{tag}.out")), dir.join(format!("{tag}.err")));
        let mut cmd = Command::new(bin(bin_name));
        cmd.args(args)
            .env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .stdin(Stdio::null())
            .stdout(std::fs::File::create(&out).unwrap())
            .stderr(std::fs::File::create(&err).unwrap());
        for (k, v) in env {
            cmd.env(k, v);
        }
        Proc { child: cmd.spawn().unwrap(), out, err }
    }

    pub fn wait(&mut self, limit: Duration) -> Option<i32> {
        let end = Instant::now() + limit;
        while Instant::now() < end {
            if let Ok(Some(st)) = self.child.try_wait() {
                return Some(std::os::unix::process::ExitStatusExt::signal(&st).map(|s| 128 + s).or(st.code()).unwrap_or(-1));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        None
    }

    pub fn text(&self) -> String {
        format!("{}{}", std::fs::read_to_string(&self.out).unwrap_or_default(), std::fs::read_to_string(&self.err).unwrap_or_default())
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn wait_http(url: &str) {
    for _ in 0..200 {
        if (Ureq { redirects: 0 }).call("GET", url, &[], &[]).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("{url} did not come up");
}

/// Real mock provider (split channels) and broker as child processes on loopback.
pub struct Live {
    pub dir: PathBuf,
    pub front: String,
    pub back: String,
    pub broker: String,
    pub store: PathBuf,
    pub procs: Vec<Proc>,
}

pub const LIVE_CLIENT_SECRET: &str = "live-client-secret-0123456789";
pub const LIVE_COMMIT_KEY: &str = "live-commit-key-abcdef0123456789";

impl Live {
    pub fn start(access_ttl: u32) -> Live {
        let dir = temp_dir("live");
        let (pf, pb, pbr) = (free_port(), free_port(), free_port());
        let (front, back, broker) = (format!("127.0.0.1:{pf}"), format!("127.0.0.1:{pb}"), format!("127.0.0.1:{pbr}"));
        let store = dir.join("store.json");
        let ttl = access_ttl.to_string();
        let p = Proc::spawn(
            &dir,
            "mockprovider",
            "mockprovider",
            &["--listen", &front, "--backchannel-listen", &back, "--auto-approve", "true", "--access-ttl", &ttl],
            &[("SCOUT_CLIENT_SECRET", LIVE_CLIENT_SECRET)],
        );
        let b = Proc::spawn(
            &dir,
            "scoutd",
            "scoutd",
            &[
                "--listen",
                &broker,
                "--provider-auth-url",
                &format!("http://{front}/authorize"),
                "--provider-token-url",
                &format!("http://{back}/token"),
                "--provider-revoke-url",
                &format!("http://{back}/revoke"),
                "--store-file",
                store.to_str().unwrap(),
            ],
            &[("SCOUT_CLIENT_SECRET", LIVE_CLIENT_SECRET), ("SCOUT_COMMIT_KEY", LIVE_COMMIT_KEY)],
        );
        wait_http(&format!("http://{front}/healthz"));
        wait_http(&format!("http://{broker}/healthz"));
        Live {
            dir,
            front: format!("http://{front}"),
            back: format!("http://{back}"),
            broker: format!("http://{broker}"),
            store,
            procs: vec![p, b],
        }
    }

    pub fn stats(&self) -> Value {
        get(&format!("{}/debug/stats", self.front), None).1
    }

    pub fn all_output(&self) -> String {
        self.procs.iter().map(Proc::text).collect()
    }
}

impl Drop for Live {
    fn drop(&mut self) {
        self.procs.clear();
        std::fs::remove_dir_all(&self.dir).ok();
    }
}

pub fn j(v: &Value) -> Vec<u8> {
    serde_json::to_vec(v).unwrap()
}

pub fn unused() -> Value {
    json!(null)
}

pub fn alive(pid: &str) -> bool {
    Command::new("kill").args(["-0", pid]).stderr(Stdio::null()).status().map(|s| s.success()).unwrap_or(false)
}

/// Waits for a file to appear and returns its trimmed text.
pub fn wait_file(p: &Path, secs: u64) -> String {
    for _ in 0..secs * 20 {
        if let Ok(t) = std::fs::read_to_string(p) {
            if !t.trim().is_empty() {
                return t.trim().to_string();
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("{} did not appear", p.display());
}

pub fn gone_within(pid: &str, secs: u64) -> bool {
    for _ in 0..secs * 20 {
        if !alive(pid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}
