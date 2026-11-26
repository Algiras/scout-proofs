#!/usr/bin/env python3
"""SMT-based verification of the SCOUT renewal control record and delegation rule.

Two kinds of result, both discharged by Z3 (SMT-LIB 2 over linear integer
arithmetic, booleans and bit-vectors; no quantifiers):

1. Inductive-invariant proofs. For the correct model we show
     Init => Inv,   Inv /\\ T => Inv'  for every transition T,   Inv => Safety.
   Generations and operation identifiers are unbounded integers, so the result
   holds for any number of generations, retries, crashes and callers. Per-
   generation properties are stated for an arbitrary symbolic generation g0.

2. Bounded model checking of deliberately broken variants. Each variant is
   unrolled from the initial state and Z3 returns a concrete violating trace.
   (A failed induction step alone would not show reachability.)

Usage: python3 scout_smt.py [--z3 /path/to/z3] [--depth 8] [--dump DIR]
Exit 0 iff every proof obligation is unsat and every broken variant has a trace.
"""
import argparse
import copy
import os
import re
import subprocess
import sys
import tempfile

# --------------------------------------------------------------------------
# Renewal control record
# --------------------------------------------------------------------------
VARS = {
    # durable control record
    "gen": "Int",          # current renewal generation
    "reserved": "Bool",    # generation reserved for one operation identifier
    "resOp": "Int",        # the reserving operation identifier
    "closed": "Bool",      # root / control record closed
    "saved": "Bool",       # a sealed replacement is retained for replay
    "savedGen": "Int",     # generation whose renewal produced it
    "savedOp": "Int",      # operation identifier that produced it
    "savedCt": "Int",      # the sealed ciphertext (opaque value)
    "commitTok": "Int",    # token the keyed commitment currently binds
    # volatile broker state (lost on crash)
    "pend": "Bool",        # an admitted request has not yet called the provider
    "inflight": "Bool",    # provider called, commit not yet written
    "presTok": "Int",      # token carried by the admitted request
    # environment
    "provTok": "Int",      # the refresh token the provider currently accepts for this root
    # ghost (specification only)
    "exchDone": "Bool",    # a provider exchange happened for the current generation
    "lapsed": "Bool",      # the retained reply's recovery window ended
    "count0": "Int",       # provider exchanges performed for generation g0
    "c0": "Bool",          # generation g0 has been committed
    "c0ct": "Int",         # ciphertext committed for g0
    "d0": "Bool",          # some reply for g0 has been delivered
    "d0ct": "Int",         # ciphertext of that delivery
    "badTok": "Bool",      # client credential used with a token that is not the root's current token
    "badReplay": "Bool",   # two deliveries for g0 differ, or differ from the committed ciphertext
    "badClosed": "Bool",   # a reply was released after closure
}
CONST = {"g0": "Int"}

INIT = """(and (= gen 0) (not reserved) (not closed) (not saved) (not pend) (not inflight)
 (= commitTok provTok) (not exchDone) (not lapsed) (= count0 0) (not c0) (not d0)
 (not badTok) (not badReplay) (not badClosed) (>= g0 0))"""

SAFETY = {
    "S1 at most one provider exchange per generation": "(<= count0 1)",
    "S2 client credential used only with the root's current token": "(not badTok)",
    "S3 every delivery for a generation is the committed ciphertext": "(not badReplay)",
    "S4 no reply released after closure": "(not badClosed)",
    "S5 a committed reply stays retrievable until retired, lapsed or closed":
        "(=> (and c0 (= gen (+ g0 1)) (not reserved) (not closed) (not lapsed))"
        " (and saved (= savedGen g0) (= savedCt c0ct)))",
}

AUX = [
    "(>= gen 0)", "(>= g0 0)",
    "(=> (< gen g0) (and (= count0 0) (not c0) (not d0)))",
    "(=> (= gen g0) (and (= count0 (ite exchDone 1 0)) (not c0) (not d0)))",
    "(=> (> gen g0) (and (= count0 1) c0))",
    "(=> pend (and reserved (not exchDone) (not inflight) (= presTok commitTok)))",
    "(=> inflight (and reserved exchDone))",
    "(=> exchDone reserved)",
    "(=> (not exchDone) (= commitTok provTok))",
    "(=> saved (and (= savedGen (- gen 1)) (not closed) (not reserved) (not lapsed)))",
    "(=> (and saved (= savedGen g0)) (and c0 (= savedCt c0ct)))",
    "(=> d0 (and c0 (= d0ct c0ct)))",
]

# name -> (params, guard, updates)
TRANS = {
    # Admission: live record, generation free, presented token matches the commitment.
    # Admitting the next generation retires the previous retained reply.
    "Reserve": ({"op": "Int", "t": "Int"},
                "(and (not closed) (not reserved) (= t commitTok))",
                {"reserved": "true", "resOp": "op", "pend": "true", "presTok": "t", "saved": "false"}),
    # The admitted request calls the provider once. The provider may or may not rotate.
    "Exchange": ({"newTok": "Int"},
                 "pend",
                 {"pend": "false", "inflight": "true", "exchDone": "true",
                  "count0": "(+ count0 (ite (= gen g0) 1 0))",
                  "badTok": "(or badTok (not (= presTok provTok)))",
                  "provTok": "newTok"}),
    # Single conditional write: sealed reply, next commitment and next generation together.
    "Commit": ({"ct": "Int"},
               "(and inflight reserved (not closed))",
               {"inflight": "false", "reserved": "false", "exchDone": "false", "lapsed": "false",
                "saved": "true", "savedGen": "gen", "savedOp": "resOp", "savedCt": "ct",
                "commitTok": "provTok", "gen": "(+ gen 1)",
                "c0": "(or c0 (= gen g0))", "c0ct": "(ite (= gen g0) ct c0ct)"}),
    # First delivery and every retry read the retained ciphertext.
    "Replay": ({"op": "Int"},
               "(and (not closed) saved (= savedOp op))",
               {"d0": "(or d0 (= savedGen g0))",
                "d0ct": "(ite (= savedGen g0) savedCt d0ct)",
                "badReplay": "(or badReplay (and (= savedGen g0)"
                             " (or (not (= savedCt c0ct)) (and d0 (not (= d0ct savedCt))))))",
                "badClosed": "(or badClosed closed)"}),
    # Broker crash, restart or timeout: volatile state is lost, the reservation is not released.
    "Crash": ({}, "true", {"pend": "false", "inflight": "false"}),
    # Closure removes retained ciphertext and blocks admission, completion and release.
    "Close": ({}, "true", {"closed": "true", "saved": "false"}),
    # Recovery window ends.
    "Expire": ({}, "saved", {"saved": "false", "lapsed": "true"}),
}


def renewal_variant(name):
    t = copy.deepcopy(TRANS)
    if name == "release_reservation_on_timeout":
        t["Crash"][2]["reserved"] = "false"
    elif name == "no_commitment_check":
        t["Reserve"] = (t["Reserve"][0], "(and (not closed) (not reserved))", t["Reserve"][2])
    elif name == "competing_operation_admitted":
        t["Reserve"] = (t["Reserve"][0], "(and (not closed) (= t commitTok))", t["Reserve"][2])
    elif name == "generation_advances_without_stored_reply":
        u = dict(t["Commit"][2])
        for k in ("saved", "savedGen", "savedOp", "savedCt"):
            del u[k]
        t["Commit"] = (t["Commit"][0], t["Commit"][1], u)
    elif name == "reseal_on_retry":
        p, g, u = t["Replay"]
        p = dict(p, fresh="Int")
        u = dict(u)
        u["d0ct"] = "(ite (= savedGen g0) fresh d0ct)"
        u["badReplay"] = ("(or badReplay (and (= savedGen g0)"
                          " (or (not (= fresh c0ct)) (and d0 (not (= d0ct fresh))))))")
        t["Replay"] = (p, g, u)
    elif name == "release_after_closure":
        t["Close"] = ({}, "true", {"closed": "true"})
        t["Replay"] = (t["Replay"][0], "(and saved (= savedOp op))", t["Replay"][2])
    else:
        raise SystemExit(f"unknown variant {name}")
    return t


VARIANTS = {
    "release_reservation_on_timeout": "S1 at most one provider exchange per generation",
    "no_commitment_check": "S2 client credential used only with the root's current token",
    "competing_operation_admitted": "S1 at most one provider exchange per generation",
    "generation_advances_without_stored_reply": "S5 a committed reply stays retrievable until retired, lapsed or closed",
    "reseal_on_retry": "S3 every delivery for a generation is the committed ciphertext",
    "release_after_closure": "S4 no reply released after closure",
}

# --------------------------------------------------------------------------
# SMT plumbing
# --------------------------------------------------------------------------
ID = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def rename(expr, mapping):
    return ID.sub(lambda m: mapping.get(m.group(0), m.group(0)), expr)


def decls(names, suffix=""):
    return "".join(f"(declare-const {n}{suffix} {s})\n" for n, s in names.items())


def z3(z3bin, script, want_model=False):
    with tempfile.NamedTemporaryFile("w", suffix=".smt2", delete=False) as f:
        f.write(script)
        path = f.name
    try:
        out = subprocess.run([z3bin, "-T:120", path], capture_output=True, text=True).stdout
    finally:
        os.unlink(path)
    lines = out.strip().splitlines()
    return (lines[0] if lines else "error"), ("\n".join(lines[1:]) if want_model else "")


def step_formula(trans, pre, post):
    """Encoding of one named transition between two renamings of the state."""
    params, guard, upd = trans
    parts = [rename(guard, pre)]
    for v in pre:
        rhs = rename(upd[v], pre) if v in upd else pre[v]
        parts.append(f"(= {post[v]} {rhs})")
    return "(and " + " ".join(parts) + ")"


def prove_inductive(z3bin, dump, M):
    VARS, CONST, INIT, SAFETY, AUX, TRANS = (M[k] for k in ("vars", "const", "init", "safety", "aux", "trans"))
    inv = "(and " + " ".join(list(SAFETY.values()) + AUX) + ")"
    pre = {v: v for v in VARS}
    post = {v: v + "_n" for v in VARS}
    head = decls(VARS) + decls(VARS, "_n") + decls(CONST)
    obligations = []
    obligations.append(("Init => Inv", head + f"(assert {INIT})\n(assert (not {inv}))\n(check-sat)\n"))
    for name, tr in TRANS.items():
        body = head + decls(tr[0])
        body += f"(assert {inv})\n(assert {step_formula(tr, pre, post)})\n"
        body += f"(assert (not {rename(inv, post)}))\n(check-sat)\n"
        obligations.append((f"Inv /\\ {name} => Inv'", body))
    ok = True
    for label, script in obligations:
        res, _ = z3(z3bin, script)
        ok &= res == "unsat"
        print(f"  {'PROVED' if res == 'unsat' else 'FAILED (' + res + ')':8} {label}")
        if dump:
            with open(os.path.join(dump, M["id"] + "__" + re.sub(r"\W+", "_", label) + ".smt2"), "w") as f:
                f.write(script)
    return ok, len(obligations)


def bmc(z3bin, M, trans, prop, depth):
    """Shortest trace from Init to a state violating `prop`, or None."""
    VARS, CONST, INIT = M["vars"], M["const"], M["init"]
    names = list(trans)
    for k in range(1, depth + 1):
        s = decls(CONST)
        for i in range(k + 1):
            s += decls(VARS, f"@{i}")
        s += f"(assert {rename(INIT, {v: v + '@0' for v in VARS})})\n"
        for i in range(k):
            pre = {v: f"{v}@{i}" for v in VARS}
            post = {v: f"{v}@{i + 1}" for v in VARS}
            s += f"(declare-const step@{i} Int)\n"
            alts = []
            for j, n in enumerate(names):
                params = {p: f"{p}@{i}" for p in trans[n][0]}
                s += decls({f"{p}@{i}_{j}": srt for p, srt in trans[n][0].items()})
                tr = (trans[n][0], rename(trans[n][1], {p: f"{p}@{i}_{j}" for p in trans[n][0]}),
                      {v: rename(e, {p: f"{p}@{i}_{j}" for p in trans[n][0]}) for v, e in trans[n][2].items()})
                alts.append(f"(and (= step@{i} {j}) {step_formula(tr, pre, post)})")
            s += "(assert (or " + " ".join(alts) + "))\n"
        s += f"(assert (not {rename(prop, {v: f'{v}@{k}' for v in VARS})}))\n(check-sat)\n"
        s += "(get-value (" + " ".join(f"step@{i}" for i in range(k)) + "))\n"
        res, model = z3(z3bin, s, want_model=True)
        if res == "sat":
            vals = dict(re.findall(r"\((step@\d+) (\d+)\)", model))
            return [names[int(vals[f"step@{i}"])] for i in range(k)]
    return None


# --------------------------------------------------------------------------
# Delegation: non-expanding authority for a chain of any length
# --------------------------------------------------------------------------
def prove_delegation(z3bin):
    """Authority is a set of exact permission tuples, encoded as a 64-bit mask.

    Inductive step for one delegation: if the parent is within the root, the
    child computed by the rule is within both parent and root, and its expiry
    and remaining budget do not exceed the parent's. By induction the property
    holds for a lineage of any depth. The broken rule (union with the request)
    is shown to violate it.
    """
    head = """(declare-const root (_ BitVec 64)) (declare-const parent (_ BitVec 64))
(declare-const req (_ BitVec 64)) (declare-const pol (_ BitVec 64)) (declare-const child (_ BitVec 64))
(declare-const rootExp Int) (declare-const parentExp Int) (declare-const reqExp Int) (declare-const childExp Int)
(declare-const parentBudget Int) (declare-const childBudget Int)
(define-fun subset ((a (_ BitVec 64)) (b (_ BitVec 64))) Bool (= (bvand a b) a))
(define-fun min2 ((a Int) (b Int)) Int (ite (<= a b) a b))
(assert (subset parent root)) (assert (<= parentExp rootExp)) (assert (> parentBudget 0))
(assert (= childExp (min2 reqExp (min2 parentExp rootExp)))) (assert (= childBudget (- parentBudget 1)))
"""
    goal = ("(assert (not (and (subset child parent) (subset child root) (<= childExp parentExp)"
            " (<= childExp rootExp) (>= childBudget 0) (< childBudget parentBudget))))\n(check-sat)\n")
    good = "(assert (= child (bvand (bvand root parent) (bvand req pol))))\n"
    bad = "(assert (= child (bvor parent (bvand req pol))))\n"
    r1, _ = z3(z3bin, head + good + goal)
    r2, _ = z3(z3bin, head + bad + goal)
    print(f"  {'PROVED' if r1 == 'unsat' else 'FAILED':8} child = root & parent & requested & policy is non-expanding (step)")
    print(f"  {'VIOLATED' if r2 == 'sat' else 'UNDETECTED':8} broken rule child = parent | (requested & policy)")
    return r1 == "unsat" and r2 == "sat"



RENEWAL = {"id": "renewal", "title": "Renewal control record (unbounded generations, operations, crashes)",
           "vars": VARS, "const": CONST, "init": INIT, "safety": SAFETY, "aux": AUX, "trans": TRANS,
           "variants": {n: (renewal_variant(n), p) for n, p in VARIANTS.items()}}

# --------------------------------------------------------------------------
# Signed single-use delivery record
# --------------------------------------------------------------------------
def release(x):
    return {"rel": "true", "relResp": x,
            "badDiff": f"(or badDiff (and rel (not (= relResp {x}))))",
            "badRev": "(or badRev (= status 2))"}

D_TRANS = {
    # first accepted retrieval: conditional write of consumed marker, request fingerprint, sealed response
    "Fetch": ({"req": "Int", "r": "Int"}, "(and (= status 0) (not delivered))",
              dict(release("r"), delivered="true", fp="req", resp="r", status="1")),
    # identical signed request: same retained response
    "Refetch": ({"req": "Int"}, "(and (= status 1) delivered (= req fp))", release("resp")),
    # a different valid request closes delivery and revokes the session
    "FetchOther": ({"req": "Int"}, "(and (= status 1) delivered (not (= req fp)))", {"status": "2"}),
    "Revoke": ({}, "true", {"status": "2"}),
}
D_VARIANTS = {}
_t = copy.deepcopy(D_TRANS)
_t["FetchOther"] = ({"req": "Int", "r": "Int"}, "(and (= status 1) delivered (not (= req fp)))", release("r"))
D_VARIANTS["new_proof_gets_new_response"] = (_t, "D1 every released response is the first one")
_t = copy.deepcopy(D_TRANS)
_t["SessionWrite"] = ({}, "(= status 1)", {"delivered": "false", "status": "0"})
D_VARIANTS["session_write_resets_delivery"] = (_t, "D1 every released response is the first one")
_t = copy.deepcopy(D_TRANS)
_t["Refetch"] = ({"req": "Int"}, "(and delivered (= req fp))", release("resp"))
D_VARIANTS["refetch_ignores_revocation"] = (_t, "D2 nothing is released after revocation")

DELIVERY = {"id": "delivery", "title": "Signed single-use delivery record",
            "vars": {"status": "Int", "delivered": "Bool", "fp": "Int", "resp": "Int",
                     "rel": "Bool", "relResp": "Int", "badDiff": "Bool", "badRev": "Bool"},
            "const": {},
            "init": "(and (= status 0) (not delivered) (not rel) (not badDiff) (not badRev))",
            "safety": {"D1 every released response is the first one": "(not badDiff)",
                       "D2 nothing is released after revocation": "(not badRev)"},
            "aux": ["(and (>= status 0) (<= status 2))", "(=> (= status 0) (and (not delivered) (not rel)))",
                    "(=> (= status 1) delivered)", "(=> rel delivered)", "(=> delivered (and rel (= relResp resp)))"],
            "trans": D_TRANS, "variants": D_VARIANTS}

# --------------------------------------------------------------------------
# Session lifecycle: bind before mint, principal lock, terminal states
# states: 0 PENDING 1 BOUND 2 AUTHORIZED 3 ACTIVE 4 DENIED 5 REVOKED 6 EXPIRED
# --------------------------------------------------------------------------
def consent(guard):
    return ({"u": "Int", "last": "Bool"}, guard,
            {"locked": "true", "lockedUser": "u", "anyConsent": "true",
             "firstUser": "(ite anyConsent firstUser u)",
             "badUser": "(or badUser (and anyConsent (not (= firstUser u))))",
             "minted": "true", "sealKey": "pinnedKey",
             "badMint": "(or badMint (not keyPinned))",
             "st": "(ite last 2 st)"})

F_TRANS = {
    "Bind": ({"k": "Int"}, "(= st 0)", {"st": "1", "keyPinned": "true", "pinnedKey": "k"}),
    "PredeclareLock": ({"u": "Int"}, "(and (<= st 1) (not locked))", {"locked": "true", "lockedUser": "u"}),
    # provider exchange and sealing happen only for a bound session and the locked principal
    "Consent": consent("(and (= st 1) (or (not locked) (= u lockedUser)))"),
    "Fetch": ({}, "(= st 2)", {"st": "3"}),
    "Deny": ({"u": "Int"}, "(and (<= st 1) (or (not locked) (= u lockedUser)))", {"st": "4", "term": "true"}),
    "Revoke": ({}, "(<= st 3)", {"st": "5", "term": "true"}),
    "Expire": ({}, "(<= st 3)", {"st": "6", "term": "true"}),
}
F_VARIANTS = {}
_t = copy.deepcopy(F_TRANS); _t["Consent"] = consent("(and (<= st 1) (or (not locked) (= u lockedUser)))")
F_VARIANTS["consent_before_bind"] = (_t, "F1 tokens are minted only for a pinned runner key")
_t = copy.deepcopy(F_TRANS); _t["Bind"] = ({"k": "Int"}, "(<= st 1)", {"st": "1", "keyPinned": "true", "pinnedKey": "k"})
F_VARIANTS["rebind_after_consent"] = (_t, "F2 grants are sealed to the pinned key")
_t = copy.deepcopy(F_TRANS); _t["Consent"] = consent("(= st 1)")
F_VARIANTS["no_principal_lock"] = (_t, "F3 one principal per session")
_t = copy.deepcopy(F_TRANS); _t["Reopen"] = ({}, "(= st 6)", {"st": "1"})
F_VARIANTS["expired_session_reopened"] = (_t, "F4 terminal states are absorbing")

SESSION = {"id": "session", "title": "Session lifecycle",
           "vars": {"st": "Int", "keyPinned": "Bool", "pinnedKey": "Int", "locked": "Bool", "lockedUser": "Int",
                    "anyConsent": "Bool", "firstUser": "Int", "minted": "Bool", "sealKey": "Int",
                    "term": "Bool", "badUser": "Bool", "badMint": "Bool"},
           "const": {},
           "init": "(and (= st 0) (not keyPinned) (not locked) (not anyConsent) (not minted) (not term)"
                   " (not badUser) (not badMint))",
           "safety": {"F1 tokens are minted only for a pinned runner key": "(not badMint)",
                      "F2 grants are sealed to the pinned key": "(=> minted (and keyPinned (= sealKey pinnedKey)))",
                      "F3 one principal per session": "(not badUser)",
                      "F4 terminal states are absorbing": "(=> term (>= st 4))"},
           "aux": ["(and (>= st 0) (<= st 6))", "(=> (= st 0) (and (not keyPinned) (not minted) (not anyConsent)))",
                   "(=> (and (>= st 1) (<= st 3)) keyPinned)", "(=> minted anyConsent)",
                   "(=> anyConsent (and locked (= firstUser lockedUser) keyPinned))",
                   "(=> (or (= st 2) (= st 3)) minted)"],
           "trans": F_TRANS, "variants": F_VARIANTS}

# --------------------------------------------------------------------------
# Authorization reservations against the root epoch (supervisor design)
# Tracked for one arbitrary operation; other callers are the environment.
# stage: 0 idle, 1 reserved, 2 dispatched
# --------------------------------------------------------------------------
A_TRANS = {
    # one atomic step: read root state and record the reservation
    "Reserve": ({}, "(and (= stage 0) (not rootClosed) (< now expiry))",
                {"stage": "1", "resEpoch": "epoch", "badRes": "(or badRes rootClosed (>= now expiry))"}),
    # revalidation immediately before dispatch
    "Dispatch": ({}, "(and (= stage 1) (= resEpoch epoch) (not rootClosed) (< now expiry))",
                 {"stage": "2", "badDispatch": "(or badDispatch (not (= resEpoch epoch)))"}),
    "Cancel": ({}, "(not rootClosed)", {"rootClosed": "true", "epoch": "(+ epoch 1)"}),
    "Tick": ({}, "true", {"now": "(+ now 1)"}),
}
A_VARIANTS = {}
_t = copy.deepcopy(A_TRANS)
_t["Check"] = ({}, "(and (= stage 0) (not rootClosed) (< now expiry))", {"sawOpen": "true"})
_t["Reserve"] = ({}, "(and (= stage 0) sawOpen)",
                 {"stage": "1", "resEpoch": "epoch", "badRes": "(or badRes rootClosed (>= now expiry))"})
A_VARIANTS["check_then_reserve"] = (_t, "A1 no reservation after closure or expiry")
_t = copy.deepcopy(A_TRANS)
_t["Dispatch"] = ({}, "(= stage 1)", {"stage": "2", "badDispatch": "(or badDispatch (not (= resEpoch epoch)))"})
A_VARIANTS["dispatch_without_revalidation"] = (_t, "A2 no dispatch under a superseded epoch")

AUTHZ = {"id": "authorization", "title": "Authorization reservations against the root epoch (unbounded time and epochs)",
         "vars": {"stage": "Int", "resEpoch": "Int", "epoch": "Int", "rootClosed": "Bool", "now": "Int",
                  "sawOpen": "Bool", "badRes": "Bool", "badDispatch": "Bool"},
         "const": {"expiry": "Int"},
         "init": "(and (= stage 0) (= epoch 0) (not rootClosed) (= now 0) (not sawOpen) (not badRes) (not badDispatch))",
         "safety": {"A1 no reservation after closure or expiry": "(not badRes)",
                    "A2 no dispatch under a superseded epoch": "(not badDispatch)"},
         "aux": ["(and (>= stage 0) (<= stage 2))", "(=> (>= stage 1) (<= resEpoch epoch))", "(not sawOpen)"],
         "trans": A_TRANS, "variants": A_VARIANTS}


# --------------------------------------------------------------------------
# Cooperative teardown and closure
# resp: 1 provider acknowledged, 2 unsupported, 3 explicit failure, 4 no answer
# --------------------------------------------------------------------------
def revoke(guard, reported="(= resp 1)"):
    return ({"d": "Bool", "resp": "Int"}, guard,
            {"badForeign": "(or badForeign (not d))",
             "badNoKey": "(or badNoKey (not keyPresent))",
             "reportedRevoked": reported, "provAck": "(= resp 1)",
             "badFalseAck": f"(or badFalseAck (and {reported} (not (= resp 1))))"})

T_TRANS = {
    # d: the submitted token is one delivered in a grant of this session (keyed digest recorded at sealing)
    "Revoke": revoke("(and keyPresent d (>= resp 1) (<= resp 4))"),
    # finalization, step 1: conditional close of the shared delivery-and-renewal record
    "Close": ({}, "(not closed)", {"closed": "true", "saved": "false", "bindings": "false"}),
    # finalization, step 2: delete session records and the pinned runner key
    "Delete": ({}, "(and closed (not deleted))", {"deleted": "true", "keyPresent": "false"}),
    "Deliver": ({}, "(not closed)", {"badAfterClose": "(or badAfterClose closed)"}),
    "RenewAdmit": ({}, "(and (not closed) bindings)", {"badAfterClose": "(or badAfterClose closed)"}),
    "RenewCommit": ({}, "(and (not closed) bindings)", {"saved": "true", "badAfterClose": "(or badAfterClose closed)"}),
}
T_VARIANTS = {}
_t = copy.deepcopy(T_TRANS); _t["Revoke"] = revoke("(and keyPresent (>= resp 1) (<= resp 4))")
T_VARIANTS["revoke_any_submitted_token"] = (_t, "T1 client credential revokes only tokens delivered in this session")
_t = copy.deepcopy(T_TRANS); _t["Revoke"] = revoke("(and keyPresent d (>= resp 1) (<= resp 4))", "(not (= resp 2))")
T_VARIANTS["error_or_timeout_reported_as_revoked"] = (_t, "T2 revoked is reported only on provider acknowledgement")
_t = copy.deepcopy(T_TRANS); _t["RenewCommit"] = ({}, "bindings", {"saved": "true", "badAfterClose": "(or badAfterClose closed)"})
_t["Close"] = ({}, "(not closed)", {"closed": "true", "saved": "false"})
T_VARIANTS["renewal_completes_after_closure"] = (_t, "T3 no delivery, renewal admission or completion after closure")
_t = copy.deepcopy(T_TRANS); _t["Delete"] = ({}, "(not deleted)", {"deleted": "true", "keyPresent": "false"})
T_VARIANTS["delete_before_close"] = (_t, "T4 records and the runner key are deleted only after closure")
_t = copy.deepcopy(T_TRANS); _t["Close"] = ({}, "(not closed)", {"closed": "true"})
T_VARIANTS["closure_keeps_ciphertext"] = (_t, "T5 closure leaves no bindings or saved ciphertext")
_t = copy.deepcopy(T_TRANS); _t["Revoke"] = revoke("(and d (>= resp 1) (<= resp 4))")
_t["Delete"] = ({}, "(not deleted)", {"deleted": "true", "keyPresent": "false", "closed": "true", "saved": "false", "bindings": "false"})
T_VARIANTS["revoke_after_key_deleted"] = (_t, "T6 revocation requests are verified against a retained runner key")

TEARDOWN = {"id": "teardown", "title": "Cooperative teardown and closure",
            "vars": {"closed": "Bool", "deleted": "Bool", "keyPresent": "Bool", "saved": "Bool", "bindings": "Bool",
                     "reportedRevoked": "Bool", "provAck": "Bool", "badForeign": "Bool", "badFalseAck": "Bool",
                     "badAfterClose": "Bool", "badNoKey": "Bool"},
            "const": {},
            "init": "(and (not closed) (not deleted) keyPresent (not saved) bindings (not reportedRevoked) (not provAck)"
                    " (not badForeign) (not badFalseAck) (not badAfterClose) (not badNoKey))",
            "safety": {"T1 client credential revokes only tokens delivered in this session": "(not badForeign)",
                       "T2 revoked is reported only on provider acknowledgement":
                           "(and (not badFalseAck) (=> reportedRevoked provAck))",
                       "T3 no delivery, renewal admission or completion after closure": "(not badAfterClose)",
                       "T4 records and the runner key are deleted only after closure":
                           "(and (=> deleted closed) (=> (not deleted) keyPresent))",
                       "T5 closure leaves no bindings or saved ciphertext": "(=> closed (and (not saved) (not bindings)))",
                       "T6 revocation requests are verified against a retained runner key": "(not badNoKey)"},
            "aux": [], "trans": T_TRANS, "variants": T_VARIANTS}

# --------------------------------------------------------------------------
# Assertion-mediated renewal (the broker never receives the refresh token)
# --------------------------------------------------------------------------
def m_reserve(guard):
    return ({"op": "Int"}, guard,
            {"reserved": "true", "resOp": "op", "expired": "false", "exchanged": "false",
             "count0": "(+ count0 (ite (= gen g0) 1 0))",
             "badIssue": "(or badIssue closed (not live) (not (= runnerDig commitDig)))"})

M_TRANS = {
    # validation, reservation and issuance of the one client assertion for this generation
    "ReserveIssue": m_reserve("(and (not closed) live (not reserved) (= runnerDig commitDig))"),
    # a matching retry within the assertion lifetime receives the same sealed assertion
    "Retry": ({"op": "Int"}, "(and reserved (= op resOp) (not expired) (not closed))",
              {"badLate": "(or badLate expired closed)"}),
    "AssertionExpires": ({}, "reserved", {"expired": "true"}),
    # the runner presents refresh token and assertion directly to the provider
    "RunnerExchange": ({"newDig": "Int"}, "(and reserved (not expired) (not exchanged))",
                       {"exchanged": "true", "runnerDig": "newDig"}),
    # signed completion report; the broker cannot verify the reported digest
    "Complete": ({"r": "Int"}, "(and reserved (not closed))",
                 {"reserved": "false", "commitDig": "r", "gen": "(+ gen 1)"}),
    "Close": ({}, "true", {"closed": "true"}),
    "SessionEnds": ({}, "true", {"live": "false"}),
}
M_VARIANTS = {}
_t = copy.deepcopy(M_TRANS)
_t["Retry"] = ({"op": "Int"}, "(and reserved (= op resOp) (not expired) (not closed))",
               {"count0": "(+ count0 (ite (= gen g0) 1 0))", "badLate": "(or badLate expired closed)"})
M_VARIANTS["fresh_assertion_on_retry"] = (_t, "M1 at most one client assertion per generation")
_t = copy.deepcopy(M_TRANS); _t["AssertionExpires"] = ({}, "reserved", {"expired": "true", "reserved": "false"})
M_VARIANTS["reservation_released_when_assertion_expires"] = (_t, "M1 at most one client assertion per generation")
_t = copy.deepcopy(M_TRANS); _t["ReserveIssue"] = m_reserve("(and (not closed) live (not reserved))")
M_VARIANTS["issue_without_digest_check"] = (_t, "M2 assertions only for a live, open session whose committed digest matches the held token")
_t = copy.deepcopy(M_TRANS); _t["ReserveIssue"] = m_reserve("(and live (not reserved) (= runnerDig commitDig))")
M_VARIANTS["issue_after_closure"] = (_t, "M2 assertions only for a live, open session whose committed digest matches the held token")
_t = copy.deepcopy(M_TRANS)
_t["Retry"] = ({"op": "Int"}, "(and reserved (= op resOp) (not closed))", {"badLate": "(or badLate expired closed)"})
M_VARIANTS["assertion_returned_after_expiry"] = (_t, "M3 no assertion is returned after expiry or closure")

ASSERTION = {"id": "assertion", "title": "Assertion-mediated renewal (unbounded generations and operations)",
             "vars": {"gen": "Int", "reserved": "Bool", "resOp": "Int", "expired": "Bool", "exchanged": "Bool",
                      "closed": "Bool", "live": "Bool", "commitDig": "Int", "runnerDig": "Int",
                      "count0": "Int", "badIssue": "Bool", "badLate": "Bool"},
             "const": {"g0": "Int"},
             "init": "(and (= gen 0) (not reserved) (not expired) (not exchanged) (not closed) live"
                     " (= commitDig runnerDig) (= count0 0) (not badIssue) (not badLate) (>= g0 0))",
             "safety": {"M1 at most one client assertion per generation": "(<= count0 1)",
                        "M2 assertions only for a live, open session whose committed digest matches the held token": "(not badIssue)",
                        "M3 no assertion is returned after expiry or closure": "(not badLate)"},
             "aux": ["(>= gen 0)", "(>= g0 0)", "(=> (< gen g0) (= count0 0))",
                     "(=> (= gen g0) (= count0 (ite reserved 1 0)))", "(=> (> gen g0) (<= count0 1))"],
             "trans": M_TRANS, "variants": M_VARIANTS}

MODELS = [SESSION, DELIVERY, RENEWAL, ASSERTION, TEARDOWN, AUTHZ]


# --------------------------------------------------------------------------
# Custody closure: what each attacker position can derive (perfect cryptography)
# --------------------------------------------------------------------------
RULES = [  # (premises, conclusion)
    ({"sealed_tokens", "runner_decryption_key"}, "refresh_token"),
    ({"sealed_tokens", "runner_decryption_key"}, "access_token"),
    # direct refresh at a provider that authenticates the confidential client
    ({"refresh_token", "client_credential"}, "new_access_token"),
    # refresh through the broker: live session, signing proof, and the key to open the sealed reply
    ({"refresh_token", "runner_signing_key", "live_session", "runner_decryption_key"}, "new_access_token"),
    # assertion-mediated: the broker signs, the holder of the refresh token redeems
    ({"refresh_token", "client_assertion"}, "new_access_token"),
    ({"runner_signing_key", "live_session", "runner_decryption_key", "refresh_token"}, "client_assertion"),
    # public-client provider: no client authentication at refresh
    ({"refresh_token", "provider_allows_public_refresh"}, "new_access_token"),
]
POSITIONS = {
    "Snapshot of broker storage": {"sealed_tokens", "token_commitment", "session_secret_hash", "runner_public_keys"},
    "Storage snapshot plus broker secrets at rest": {"sealed_tokens", "token_commitment", "session_secret_hash",
                                                     "runner_public_keys", "client_credential", "commitment_key"},
    "Network observer of runner-broker traffic (TLS intact)": {"sealed_tokens", "runner_public_keys"},
    "Workload (environment surface)": {"access_token"},
    "Runner memory, session closed": {"refresh_token", "access_token", "runner_decryption_key", "runner_signing_key"},
    "Runner memory, session live": {"refresh_token", "access_token", "runner_decryption_key", "runner_signing_key",
                                    "live_session"},
    "Runner memory, session closed, public-client provider": {"refresh_token", "access_token", "runner_decryption_key",
                                                              "runner_signing_key", "provider_allows_public_refresh"},
    "Live broker process during a renewal (implemented profile)": {"client_credential", "commitment_key",
                                                                   "refresh_token", "access_token"},
    "Live broker process (assertion-mediated design)": {"client_credential", "commitment_key", "token_digest"},
}
EXPECT_NEW = {"Runner memory, session live", "Runner memory, session closed, public-client provider",
              "Live broker process during a renewal (implemented profile)"}


def closure(known):
    known = set(known)
    changed = True
    while changed:
        changed = False
        for pre, post in RULES:
            if pre <= known and post not in known:
                known.add(post)
                changed = True
    return known


def custody():
    ok = True
    print(f"  {'attacker position':58} current AT  refresh tok  new AT")
    for name, facts in POSITIONS.items():
        k = closure(facts)
        row = [x in k for x in ("access_token", "refresh_token", "new_access_token")]
        ok &= row[2] == (name in EXPECT_NEW)
        print(f"  {name:58} {'yes' if row[0] else 'no':10}  {'yes' if row[1] else 'no':11}  {'yes' if row[2] else 'no'}")
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--z3", default="z3")
    ap.add_argument("--depth", type=int, default=8)
    ap.add_argument("--dump", help="write the induction obligations as .smt2 files")
    a = ap.parse_args()
    if a.dump:
        os.makedirs(a.dump, exist_ok=True)
    print(subprocess.run([a.z3, "--version"], capture_output=True, text=True).stdout.strip())
    ok, total, nvar = True, 0, 0
    for M in MODELS:
        print(f"\n== {M['title']} ==")
        print(" inductive invariant:")
        good, n = prove_inductive(a.z3, a.dump, M)
        ok &= good
        total += n
        print(f" proved for all reachable states: {'; '.join(M['safety'])}")
        clean = all(bmc(a.z3, M, M["trans"], p, a.depth) is None for p in M["safety"].values())
        ok &= clean
        print(f" sanity: bounded search to depth {a.depth} on the correct model finds "
              f"{'no violation' if clean else 'A VIOLATION'}")
        print(" broken variants (shortest violating trace):")
        for name, (trans, label) in M["variants"].items():
            trace = bmc(a.z3, M, trans, M["safety"][label], a.depth)
            ok &= trace is not None
            nvar += 1
            print(f"  {name}: violates {label.split(' ')[0]} by "
                  f"{' -> '.join(trace) if trace else 'NO TRACE FOUND'}")
    print("\n== Delegation rule ==")
    ok &= prove_delegation(a.z3)
    print("\n== Custody closure (symbolic, perfect cryptography) ==")
    ok &= custody()
    print(f"\nRESULT: {'all' if ok else 'NOT all'} obligations discharged "
          f"({total} induction obligations, {nvar} broken variants with traces)")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
