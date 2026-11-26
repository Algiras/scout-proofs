// SPDX-License-Identifier: Apache-2.0

//! Exhaustive breadth-first exploration of the renewal logic: the real store,
//! the real `scout-core` step function and an injectable clock. Every reachable
//! state is checked against S1-S5; states are deduplicated on store contents
//! plus the volatile and ghost bookkeeping.
use scout_broker::provider::{ProvErr, Refresher, Tokens};
use scout_broker::records::{ctl_key, parse, Control};
use scout_broker::renewal::{BeginOut, BeginReq, Claim, NewControl, RenewErr, Renewer};
use scout_broker::store::{MemStore, Store};
use scout_core::Reject;
use scout_wire::seal;
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

const T0: u64 = 1_000_000;
const DEADLINE: u64 = T0 + 3600;
const SID: &str = "s";
const MAX_GEN: u32 = 2;

/// Rotates tok-N to tok-(N+1).
struct Fake;
impl Refresher for Fake {
    fn refresh(&self, t: &str) -> Result<Tokens, ProvErr> {
        let n: u32 = t.strip_prefix("tok-").and_then(|n| n.parse().ok()).ok_or(ProvErr::Rejected(400))?;
        Ok(Tokens { access: format!("acc-{}", n + 1), refresh: Some(format!("tok-{}", n + 1)), expires_in: 60 })
    }
}

#[derive(Clone, Copy, Debug)]
enum Tok {
    Cur,
    Foreign,
    Prev,
}

#[derive(Clone, Copy, Debug)]
enum Act {
    Begin(&'static str, Tok),
    Exchange,
    Complete,
    Crash,
    Close,
    Lapse,
}

#[derive(Clone)]
struct Worker {
    claim: Claim,
    presented: String,
    tokens: Option<Tokens>,
}

struct World {
    store: Arc<MemStore>,
    clock: Arc<AtomicU64>,
    r: Renewer,
    lapsed: bool,
    closed: bool,
    admits: BTreeMap<u32, u32>,
    exchanges: BTreeMap<u32, u32>,
    /// generation -> (reply, operation, recovery window end)
    committed: BTreeMap<u32, (Vec<u8>, &'static str, u64)>,
    receipts: BTreeMap<u32, String>,
    worker: Option<Worker>,
}

impl World {
    fn new() -> World {
        let store = Arc::new(MemStore::new());
        let clock = Arc::new(AtomicU64::new(T0));
        let c2 = clock.clone();
        let r = Renewer::new(store.clone(), b"commit-key-0123456789abcdef".to_vec(), "client", Arc::new(move || c2.load(Ordering::SeqCst)));
        let (_, enc_pub) = seal::keypair();
        let nc = NewControl { session: SID, grant: "g", capability: "default", enc_pub, sig_pub: [7; 32], deadline: DEADLINE };
        r.init_control(&nc, &Tokens { access: "acc-0".into(), refresh: Some("tok-0".into()), expires_in: 60 }).unwrap();
        let mut w = World {
            store,
            clock,
            r,
            lapsed: false,
            closed: false,
            admits: Default::default(),
            exchanges: Default::default(),
            committed: Default::default(),
            receipts: Default::default(),
            worker: None,
        };
        w.receipts.insert(0, w.ctl().receipt);
        w
    }

    fn fork(&self) -> World {
        let store = Arc::new(self.store.snapshot());
        let clock = Arc::new(AtomicU64::new(self.clock.load(Ordering::SeqCst)));
        let c2 = clock.clone();
        let r = self.r.fork(store.clone(), Arc::new(move || c2.load(Ordering::SeqCst)));
        World {
            store,
            clock,
            r,
            lapsed: self.lapsed,
            closed: self.closed,
            admits: self.admits.clone(),
            exchanges: self.exchanges.clone(),
            committed: self.committed.clone(),
            receipts: self.receipts.clone(),
            worker: self.worker.clone(),
        }
    }

    fn now(&self) -> u64 {
        self.clock.load(Ordering::SeqCst)
    }

    fn ctl(&self) -> Control {
        parse(&self.store.get(&ctl_key(SID)).unwrap().unwrap()).unwrap()
    }

    fn actions(&self) -> Vec<Act> {
        let gen = self.ctl().ctl.gen;
        let mut v = vec![Act::Crash, Act::Close];
        for op in ["A", "B"] {
            if gen < MAX_GEN {
                v.push(Act::Begin(op, Tok::Cur));
                v.push(Act::Begin(op, Tok::Foreign));
            }
            if gen >= 1 {
                v.push(Act::Begin(op, Tok::Prev));
            }
        }
        match &self.worker {
            Some(w) if w.tokens.is_some() => v.push(Act::Complete),
            Some(_) => v.push(Act::Exchange),
            None => {}
        }
        if !self.lapsed {
            v.push(Act::Lapse);
        }
        v
    }

    fn request(&self, op: &'static str, tok: Tok) -> (u32, String, String, &'static str) {
        let gen = self.ctl().ctl.gen;
        let (g, t) = match tok {
            Tok::Cur => (gen, format!("tok-{gen}")),
            Tok::Foreign => (gen, "tok-foreign".to_string()),
            Tok::Prev => (gen - 1, format!("tok-{}", gen - 1)),
        };
        (g, t, self.receipts[&g].clone(), op)
    }

    fn apply(&mut self, a: Act) {
        match a {
            Act::Begin(op, tok) => {
                let (g, token, receipt, op) = self.request(op, tok);
                let q = BeginReq { session: SID, op, gen: g, receipt: &receipt, token: &token };
                match self.r.begin(&q) {
                    Ok(BeginOut::Reserved(claim)) => {
                        assert!(matches!(tok, Tok::Cur), "S2: admitted on a non-current token");
                        assert!(!self.closed, "S4: admitted after closure");
                        let n = self.admits.entry(g).or_default();
                        *n += 1;
                        assert!(*n <= 1, "S1: second admission for generation {g}");
                        assert!(self.worker.is_none());
                        self.worker = Some(Worker { claim, presented: token, tokens: None });
                    }
                    Ok(BeginOut::Replay(bytes)) => {
                        assert!(!self.closed, "S4: reply released after closure");
                        let (reply, committer, until) = self.committed.get(&(g + 1)).expect("S3: replay without a commit");
                        assert_eq!(&bytes, reply, "S3: recovered reply differs from the committed one");
                        assert_eq!(*committer, op, "S3: reply released to another operation");
                        assert!(self.now() <= *until, "S5: reply released after lapse");
                    }
                    Err(e) => {
                        if self.closed {
                            assert_eq!(e, RenewErr::Reject(Reject::Closed), "S4");
                        }
                    }
                }
            }
            Act::Exchange => {
                let presented = self.worker.as_ref().unwrap().presented.clone();
                match self.r.permit_exchange(SID) {
                    Ok(()) => {
                        assert!(!self.closed, "S4: provider used after closure");
                        let g = self.ctl().ctl.gen;
                        let n = self.exchanges.entry(g).or_default();
                        *n += 1;
                        assert!(*n <= 1, "S1: second provider exchange for generation {g}");
                        self.worker.as_mut().unwrap().tokens = Some(Fake.refresh(&presented).unwrap());
                    }
                    Err(e) => {
                        assert_eq!(e, RenewErr::Reject(Reject::Closed));
                        assert!(self.closed);
                        self.r.crash(SID);
                        self.worker = None;
                    }
                }
            }
            Act::Complete => {
                let w = self.worker.take().unwrap();
                match self.r.commit(SID, &w.claim, w.tokens.as_ref().unwrap(), &w.presented) {
                    Ok(reply) => {
                        assert!(!self.closed, "S4: completed after closure");
                        let g = self.ctl().ctl.gen;
                        let until = (self.now() + 600).min(DEADLINE);
                        assert!(self.committed.insert(g, (reply, if w.claim.op == "A" { "A" } else { "B" }, until)).is_none());
                        self.receipts.insert(g, self.ctl().receipt);
                    }
                    Err(e) => {
                        assert_eq!(e, RenewErr::Reject(Reject::Closed), "S4");
                        assert!(self.closed);
                        self.r.crash(SID);
                    }
                }
            }
            Act::Crash => {
                self.r.crash(SID);
                self.worker = None;
            }
            Act::Close => {
                self.r.close(SID).unwrap();
                self.closed = true;
            }
            Act::Lapse => {
                self.clock.fetch_add(11 * 60, Ordering::SeqCst);
                self.lapsed = true;
            }
        }
    }

    /// Deduplication key: store contents (ciphertext bytes reduced to their length)
    /// plus volatile and ghost bookkeeping.
    fn key(&self) -> String {
        let mut s = String::new();
        for (k, v) in self.store.dump() {
            let mut j: serde_json::Value = serde_json::from_slice(&v).unwrap();
            for f in ["saved_reply", "initial_grant"] {
                let n = j[f].as_str().map(str::len).unwrap_or(0);
                j[f] = n.into();
            }
            s += &format!("{k}={j};");
        }
        let committed: Vec<_> = self.committed.iter().map(|(g, (_, op, u))| (g, op, u)).collect();
        let worker = self.worker.as_ref().map(|w| (&w.claim, &w.presented, w.tokens.is_some()));
        s + &format!(
            "{:?}|{:?}|{}|{}|{:?}|{:?}|{:?}|{:?}",
            self.r.volatile(),
            worker,
            self.now(),
            self.closed,
            self.admits,
            self.exchanges,
            committed,
            self.receipts.len()
        )
    }

    /// S1-S5 on a reachable state.
    fn check(&self) {
        let c = self.ctl();
        assert!(self.admits.values().chain(self.exchanges.values()).all(|n| *n <= 1), "S1");
        assert_eq!(self.committed.len() as u32, c.ctl.gen, "S5: generation advanced without a stored reply");
        if self.closed {
            assert!(c.commit.is_empty() && c.saved_reply.is_empty() && c.claim_op.is_empty(), "S4/T5: closure left bindings or ciphertext");
        }
        // S5/S3: the committed reply stays retrievable by its operation until the next
        // admission, lapse or closure, and not after.
        let g = c.ctl.gen;
        if g >= 1 {
            let (reply, op, until) = &self.committed[&g];
            let expect = !self.closed && !self.admits.contains_key(&g) && self.now() <= *until;
            let mut probe = self.fork();
            let (pg, token, receipt, op) = {
                let tok = format!("tok-{}", g - 1);
                (g - 1, tok, self.receipts[&(g - 1)].clone(), *op)
            };
            let got = probe.r.begin(&BeginReq { session: SID, op, gen: pg, receipt: &receipt, token: &token });
            match (expect, got) {
                (true, Ok(BeginOut::Replay(b))) => assert_eq!(&b, reply, "S3"),
                (true, other) => panic!("S5: committed reply not retrievable in {}: {other:?}", self.key()),
                (false, Ok(BeginOut::Replay(_))) => panic!("S4/S5: reply released when it must not be"),
                (false, Err(e)) if self.closed => assert_eq!(e, RenewErr::Reject(Reject::Closed)),
                (false, _) => {}
            }
            probe.worker = None;
        }
    }
}

#[test]
fn renewal_state_space_satisfies_s1_to_s5() {
    let start = World::new();
    let mut seen: HashSet<String> = HashSet::new();
    seen.insert(start.key());
    let mut q = VecDeque::from([start]);
    let mut transitions = 0usize;
    while let Some(w) = q.pop_front() {
        w.check();
        for a in w.actions() {
            let mut n = w.fork();
            n.apply(a);
            transitions += 1;
            if seen.insert(n.key()) {
                q.push_back(n);
            }
        }
    }
    println!("renewal conformance (real store + core, generations 0..={MAX_GEN}): states={} transitions={transitions}", seen.len());
    assert!(seen.len() > 200);
}
