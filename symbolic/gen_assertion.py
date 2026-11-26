#!/usr/bin/env python3
"""ProVerif models of SCOUT renewal under a broker compromise, and of assertion-mediated renewal.

Two phases. Phase 0: session creation, consent, initial exchange and sealed
delivery. Phase 1: renewal. In the compromise scenarios everything the broker
holds is given to the attacker at the start of phase 1 (transport key, client
credential or client signing key, commitment key), which models a broker that
is taken over after delivery and before a renewal.

Renewal modes:
  transient  - implemented profile: the runner sends the refresh token to the
               broker, which calls the provider with the client credential.
  assertion  - the runner sends only a digest; the broker returns one signed
               client assertion sealed to the runner; the runner presents the
               refresh token and the assertion to the provider itself.

Client identity (assertion mode):
  shared     - one client signing key for every session.
  per-grant  - a client identity registered per root grant.

Usage: python3 gen_assertion.py [--proverif proverif]
Exit 0 iff every query has the expected result.
"""
import argparse
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

MODEL = r"""
free net: channel.
free bp: channel [private].        (* broker <-> provider back channel; each request carries a fresh reply channel *)
free hreq: channel [private].      (* requester -> honest runner *)
free hprin: channel [private].     (* requester -> honest principal *)
free cons: channel [private].      (* honest principal's authenticated consent *)

type skey. type pkey. type sskey. type spkey. type key. type nonce.
fun pk(skey): pkey.
fun spk(sskey): spkey.
fun tenc(bitstring, pkey): bitstring.
reduc forall m: bitstring, k: skey; tdec(tenc(m, pk(k)), k) = m.
fun senc(bitstring, key): bitstring.
reduc forall m: bitstring, k: key; sdec(senc(m, k), k) = m.
fun seal(bitstring, pkey, bitstring, nonce): bitstring.
reduc forall m: bitstring, k: skey, ad: bitstring, r: nonce; unseal(seal(m, pk(k), ad, r), k, ad) = m.
fun sign(bitstring, sskey): bitstring.
reduc forall m: bitstring, k: sskey; checksign(sign(m, k), spk(k)) = m.
reduc forall m: bitstring, k: sskey; getmsg(sign(m, k)) = m.
fun hmac(bitstring, key): bitstring.
fun h(bitstring): bitstring.

const exch, refr, fetchTag, renewTag, assertTag, tagAT, tagRT, zero, one: bitstring.

table tok(bitstring, bitstring, bool, spkey).   (* refresh token, grant, honest grant, client key it was issued to *)
table tok2(bitstring, bitstring, bool).         (* rotated token; one rotation is modelled *)

event HonestToken(bitstring).
event HonestNew(bitstring).
event RunnerRenewed(bitstring, bitstring).

(* Q1 *) query x: bitstring; event(HonestToken(x)) && attacker(x) ==> false.
(* Q4 *) query x: bitstring; event(HonestNew(x)) && attacker(x) ==> false.
(* R  *) query s: bitstring, t: bitstring; event(RunnerRenewed(s, t)).

let Provider(cs: bitstring, skP: skey) =
  ( ! in(bp, (=exch, =cs, hon: bool, cvk: spkey, rc: channel));
      new at: bitstring; new rt: bitstring; new g: bitstring;
      insert tok(rt, g, hon, cvk);
      if hon = true then (event HonestToken(at); event HonestToken(rt); out(rc, (at, rt, g)))
      else out(rc, (at, rt, g)) )
  | ( ! in(bp, (=refr, =cs, rtp: bitstring, rc: channel));          (* refresh with the client secret, back channel *)
      get tok(=rtp, g, hon, cvk) in
      new at2: bitstring; new rt2: bitstring;
      insert tok2(rt2, g, hon);
      if hon = true then (event HonestToken(at2); event HonestToken(rt2);
                          event HonestNew(at2); event HonestNew(rt2); out(rc, (at2, rt2)))
      else out(rc, (at2, rt2)) )
  | ( ! in(net, (=refr, =cs, rtp: bitstring));                        (* refresh with the client secret, public endpoint *)
      get tok(=rtp, g, hon, cvk) in
      new at2: bitstring; new rt2: bitstring;
      insert tok2(rt2, g, hon);
      if hon = true then (event HonestToken(at2); event HonestToken(rt2);
                          event HonestNew(at2); event HonestNew(rt2); out(net, (at2, rt2)))
      else out(net, (at2, rt2)) )
  | ( ! in(net, m: bitstring);                                        (* refresh with a signed client assertion *)
      let ((rtp: bitstring, asrt: bitstring), k: key) = tdec(m, skP) in
      get tok(=rtp, g, hon, cvk) in
      let (=assertTag, jti: bitstring) = checksign(asrt, cvk) in
      new at2: bitstring; new rt2: bitstring;
      insert tok2(rt2, g, hon);
      if hon = true then (event HonestToken(at2); event HonestToken(rt2);
                          event HonestNew(at2); event HonestNew(rt2); out(net, senc((at2, rt2), k)))
      else out(net, senc((at2, rt2), k)) ).

let Session(skB: skey, cs: bitstring, kc: key, skC: sskey, sid: bitstring, ss: bitstring, hon: bool) =
  out(net, (sid, h(ss)));
  in(net, m1: bitstring);
  let ((=sid, =ss, pkE: pkey, vk: spkey), k1: key) = tdec(m1, skB) in
  @CONSENT@
  @CLIENTKEY@
  new rc1: channel; out(bp, (exch, cs, hon, spk(skCu), rc1));
  in(rc1, (at: bitstring, rt: bitstring, g: bitstring));
  new gid: bitstring; new r1: nonce; new r2: nonce;
  let ctA = seal(at, pkE, (sid, gid, tagAT, zero), r1) in
  let ctR = seal(rt, pkE, (sid, gid, tagRT, zero), r2) in
  let cm = @COMMITMENT@ in
  out(net, (gid, ctA, ctR, cm));
  in(net, m2: bitstring);
  let ((=sid, ts: bitstring, sg: bitstring), k2: key) = tdec(m2, skB) in
  if checksign(sg, vk) = (fetchTag, sid, ts) then
  out(net, senc((gid, ctA, ctR), k2));
  phase 1;
  @LEAKPERGRANT@
  in(net, m3: bitstring);
  @BROKERRENEW@

let Broker(skB: skey, cs: bitstring, kc: key, skC: sskey) =
  ( ! new sid: bitstring; new ss: bitstring;
      out(hprin, sid);
      ( out(hreq, (sid, ss)) | SessionH(skB, cs, kc, skC, sid, ss, true) ) )
  | ( ! new sid: bitstring; new ss: bitstring;
      out(net, (sid, ss));
      SessionA(skB, cs, kc, skC, sid, ss, false) ).

let Principal() = ! in(hprin, sid: bitstring); out(cons, sid).

let Runner(pkB: pkey, pkP: pkey) =
  ! in(hreq, (sid: bitstring, ss: bitstring));
    new skE: skey; new skS: sskey; new k1: key;
    out(net, tenc(((sid, ss, pk(skE), spk(skS)), k1), pkB));
    new ts: bitstring; new k2: key;
    out(net, tenc(((sid, ts, sign((fetchTag, sid, ts), skS)), k2), pkB));
    in(net, c: bitstring);
    let (gid: bitstring, ctA: bitstring, ctR: bitstring) = sdec(c, k2) in
    let at = unseal(ctA, skE, (sid, gid, tagAT, zero)) in
    let rt = unseal(ctR, skE, (sid, gid, tagRT, zero)) in
    @LEAKRT@
    phase 1;
    new opid: bitstring; new k3: key;
    @RUNNERRENEW@

process
  new skB: skey; new skP: skey; new cs: bitstring; new kc: key; new skC: sskey;
  out(net, pk(skB)); out(net, pk(skP));
  ( Provider(cs, skP) | (phase 1; Provider(cs, skP))
  | Broker(skB, cs, kc, skC) | Principal() | Runner(pk(skB), pk(skP))
  | (phase 1; @COMPROMISE@ 0) )
"""

TRANSIENT = {
    "COMMITMENT": "hmac((g, zero, rt), kc)",
    "BROKERRENEW": """let ((=sid, rtp: bitstring, opid: bitstring, sg3: bitstring), k3: key) = tdec(m3, skB) in
  if checksign(sg3, vk) = (renewTag, sid, h(rtp), opid) then
  if hmac((g, zero, rtp), kc) = cm then
  new rc2: channel; out(bp, (refr, cs, rtp, rc2));
  in(rc2, (at2: bitstring, rt2: bitstring));
  new gid2: bitstring; new r3: nonce; new r4: nonce;
  out(net, senc((gid2, seal(at2, pkE, (sid, gid2, tagAT, one), r3), seal(rt2, pkE, (sid, gid2, tagRT, one), r4)), k3)).""",
    "RUNNERRENEW": """out(net, tenc(((sid, rt, opid, sign((renewTag, sid, h(rt), opid), skS)), k3), pkB));
    in(net, c2: bitstring);
    let (gid2: bitstring, ctA2: bitstring, ctR2: bitstring) = sdec(c2, k3) in
    let at2 = unseal(ctA2, skE, (sid, gid2, tagAT, one)) in
    let rt2 = unseal(ctR2, skE, (sid, gid2, tagRT, one)) in
    event RunnerRenewed(sid, rt2).""",
}
ASSERTION = {
    "COMMITMENT": "hmac((g, zero, h(rt)), kc)",
    "BROKERRENEW": """let ((=sid, dg: bitstring, opid: bitstring, sg3: bitstring), k3: key) = tdec(m3, skB) in
  if checksign(sg3, vk) = (renewTag, sid, dg, opid) then
  if hmac((g, zero, dg), kc) = cm then
  new jti: bitstring; new r3: nonce;
  out(net, senc(seal(sign((assertTag, jti), skCu), pkE, (sid, assertTag, zero), r3), k3)).""",
    "RUNNERRENEW": """out(net, tenc(((sid, h(rt), opid, sign((renewTag, sid, h(rt), opid), skS)), k3), pkB));
    in(net, c2: bitstring);
    let asrt = unseal(sdec(c2, k3), skE, (sid, assertTag, zero)) in
    new k5: key;
    out(net, tenc(((rt, asrt), k5), pkP));
    in(net, c3: bitstring);
    let (at2: bitstring, rt2: bitstring) = sdec(c3, k5) in
    event RunnerRenewed(sid, rt2).""",
}
SHARED = {"CLIENTKEY": "let skCu = skC in", "LEAKPERGRANT": ""}
PERGRANT = {"CLIENTKEY": "new skCu: sskey;", "LEAKPERGRANT": ""}
PERGRANT_LEAK = {"CLIENTKEY": "new skCu: sskey;", "LEAKPERGRANT": "out(net, skCu);"}
COMPROMISE = "out(net, skB); out(net, cs); out(net, kc); out(net, skC);"

# name -> (description, parts, expected Q1, expected Q4); None = not checked
SCENARIOS = {
    "p_transient_broker_compromised_at_renewal": (
        "implemented profile; the broker is compromised after delivery, before a renewal",
        [TRANSIENT, SHARED, {"COMPROMISE": COMPROMISE, "LEAKRT": ""}], False, False),
    "p_assertion_broker_compromised_at_renewal": (
        "assertion-mediated renewal; the broker is compromised after delivery, before a renewal",
        [ASSERTION, SHARED, {"COMPROMISE": COMPROMISE, "LEAKRT": ""}], True, True),
    "p_assertion_per_grant_broker_compromised_at_renewal": (
        "assertion-mediated renewal with per-grant client identities; broker compromised, all client keys leak",
        [ASSERTION, PERGRANT_LEAK, {"COMPROMISE": COMPROMISE, "LEAKRT": ""}], True, True),
    "p_assertion_snapshot": (
        "assertion-mediated renewal; network and storage snapshot only",
        [ASSERTION, SHARED, {"COMPROMISE": "", "LEAKRT": ""}], True, True),
    "p_assertion_shared_client_stolen_token": (
        "assertion-mediated renewal, one shared client identity; a refresh token is stolen",
        [ASSERTION, SHARED, {"COMPROMISE": "", "LEAKRT": "out(net, rt);"}], None, False),
    "p_assertion_per_grant_client_stolen_token": (
        "assertion-mediated renewal, client identity per root grant; a refresh token is stolen",
        [ASSERTION, PERGRANT, {"COMPROMISE": "", "LEAKRT": "out(net, rt);"}], None, True),
}
QNAMES = ["Q1 tokens of honest grants stay secret", "Q4 tokens minted by refreshing an honest grant stay secret"]


def build(parts):
    subs = {}
    for p in parts:
        subs.update(p)
    src = MODEL
    start, end = src.index("let Session("), src.index("let Broker(")
    sess = src[start:end]
    hon = sess.replace("let Session(", "let SessionH(").replace("@CONSENT@", "in(cons, =sid);")
    att = sess.replace("let Session(", "let SessionA(").replace("@CONSENT@", "in(net, =sid);")
    src = src[:start] + hon + att + src[end:]
    for k, v in subs.items():
        src = src.replace(f"@{k}@", v)
    assert "@" not in re.sub(r"\(\*.*?\*\)", "", src, flags=re.S), "unexpanded placeholder"
    return src


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--proverif", default="proverif")
    ap.add_argument("--only")
    ap.add_argument("--timeout", type=int, default=300)
    a = ap.parse_args()
    ok = True
    for name, (desc, parts, e1, e4) in SCENARIOS.items():
        if a.only and a.only != name:
            continue
        with open(os.path.join(HERE, name + ".pv"), "w") as f:
            f.write(f"(* {desc} *)\n(* generated by gen_assertion.py; do not edit *)\n" + build(parts))
        try:
            out = subprocess.run([a.proverif, name + ".pv"], capture_output=True, text=True,
                                 timeout=a.timeout, cwd=HERE)
            text = out.stdout + out.stderr
        except subprocess.TimeoutExpired as e:
            text = (e.stdout or b"").decode() + "\nTIMEOUT\n"
        with open(os.path.join(HERE, name + ".log"), "w") as f:
            f.write(text)
        res = re.findall(r"^RESULT (.*?) (is true|is false|cannot be proved)\.", text, flags=re.M)
        print(f"\n{name}: {desc}")
        if len(res) != 3:
            ok = False
            print("  ERROR: expected 3 results, got", len(res), "\n", text[-700:])
            continue
        for i, exp in enumerate((e1, e4)):
            got = res[i][1]
            if exp is None:
                print(f"  {'n/a':10} {QNAMES[i]}")
                continue
            good = got == ("is true" if exp else "is false")
            ok &= good
            verdict = "PROVED" if got == "is true" else ("ATTACK" if got == "is false" else "NOT PROVED")
            print(f"  {verdict:10} {QNAMES[i]}{'' if good else '   <-- UNEXPECTED'}")
        reach = res[2][1] == "is false"
        ok &= reach
        print(f"  {'REACHABLE' if reach else 'UNREACHABLE':10} sanity: an honest runner completes a renewal")
    print("\nRESULT:", "all scenarios as expected" if ok else "MISMATCH")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
