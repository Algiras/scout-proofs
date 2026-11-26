#!/usr/bin/env python3
"""Export the SCOUT transition systems of scout_smt.py to TLA+ and to Lean 4.

The six models are defined once, in scout_smt.py. This script translates the
same definitions mechanically, so the three tools check the same systems:

  Z3     (scout_smt.py)  inductive invariants, SMT, unbounded
  Lean 4 (lean/)         the same inductive-invariant obligations as theorems
                         checked by the Lean kernel, unbounded
  TLA+   (tla/)          the same systems as TLA+ modules, model-checked
                         exhaustively by TLC within finite bounds; every broken
                         variant must violate its invariant

Usage:
  python3 export.py                 # write lean/
  python3 export.py --check-lean    # also run `lean` on every generated file
  python3 export.py --check-tla JAR # write tla/ and run TLC (java -cp JAR tlc2.TLC)
Exit 0 iff everything requested passes.
"""
import argparse
import os
import re
import subprocess
import sys

import scout_smt as M

HERE = os.path.dirname(os.path.abspath(__file__))


# ---------------------------------------------------------------- s-expressions
def parse(src):
    toks = re.findall(r"\(|\)|[^\s()]+", src)
    pos = 0

    def rd():
        nonlocal pos
        t = toks[pos]
        pos += 1
        if t == "(":
            out = []
            while toks[pos] != ")":
                out.append(rd())
            pos += 1
            return out
        return t

    e = rd()
    assert pos == len(toks), f"trailing tokens in {src!r}"
    return e


def subst(e, env):
    if isinstance(e, list):
        return [e[0]] + [subst(x, env) for x in e[1:]]
    return env.get(e, e)


def is_int(tok):
    return isinstance(tok, str) and re.fullmatch(r"-?\d+", tok) is not None


# ---------------------------------------------------------------- TLA+
def tla(e):
    if isinstance(e, str):
        return {"true": "TRUE", "false": "FALSE"}.get(e, e)
    op, args = e[0], [tla(x) for x in e[1:]]
    if op == "and":
        return "(" + " /\\ ".join(args) + ")"
    if op == "or":
        return "(" + " \\/ ".join(args) + ")"
    if op == "not":
        return f"~({args[0]})"
    if op == "=>":
        return f"({args[0]} => {args[1]})"
    if op == "ite":
        return f"(IF {args[0]} THEN {args[1]} ELSE {args[2]})"
    if op in ("=", "<", "<=", ">", ">=", "+", "-"):
        sym = {"<=": "=<"}.get(op, op)
        return "(" + f" {sym} ".join(args) + ")"
    raise ValueError(op)


PARAM_DOMAIN = {"resp": "1..4"}


def tla_module(name, model, trans):
    vs = dict(model["vars"])
    consts = dict(model["const"])
    allv = list(vs) + list(consts)
    sorts = dict(vs, **consts)
    out = [f"---- MODULE {name} ----", "EXTENDS Integers", "", "VARIABLES " + ", ".join(allv),
           "vars == <<" + ", ".join(allv) + ">>", ""]
    typ = [f"  /\\ {v} \\in {'BOOLEAN' if sorts[v] == 'Bool' else '0..2'}" for v in allv]
    out += ["Init ==", *typ, f"  /\\ {tla(parse(model['init']))}", ""]
    names = []
    for tn, (params, guard, upd) in trans.items():
        names.append(tn)
        unchanged = [v for v in allv if v not in upd]
        body = [f"  /\\ {tla(parse(guard))}"]
        body += [f"  /\\ {v}' = {tla(parse(e))}" for v, e in upd.items()]
        if unchanged:
            body.append("  /\\ UNCHANGED <<" + ", ".join(unchanged) + ">>")
        if params:
            quant = ", ".join(f"{p} \\in {'BOOLEAN' if s == 'Bool' else PARAM_DOMAIN.get(p, '0..1')}"
                              for p, s in params.items())
            out += [f"{tn} ==", f"  \\E {quant} :"] + ["  " + b for b in body] + [""]
        else:
            out += [f"{tn} =="] + body + [""]
    out += ["Next == " + " \\/ ".join(names), "",
            "Bound == " + " /\\ ".join(f"{v} \\in -1..4" for v in allv if sorts[v] == "Int"), ""]
    invs = []
    for i, (label, prop) in enumerate(model["safety"].items()):
        key = label.split(" ")[0]
        invs.append(key)
        out += [f"\\* {label}", f"{key} == {tla(parse(prop))}", ""]
    out += ["===="]
    return "\n".join(out) + "\n", invs


def write_tla(outdir):
    os.makedirs(outdir, exist_ok=True)
    jobs = []  # (module, invariant or None, expect_violation)
    for model in M.MODELS:
        name = "Scout_" + model["id"]
        src, invs = tla_module(name, model, model["trans"])
        open(os.path.join(outdir, name + ".tla"), "w").write(src)
        open(os.path.join(outdir, name + ".cfg"), "w").write(
            "INIT Init\nNEXT Next\nCONSTRAINT Bound\nCHECK_DEADLOCK FALSE\n" +
            "".join(f"INVARIANT {i}\n" for i in invs))
        jobs.append((name, None, False))
        for vname, (trans, label) in model["variants"].items():
            mod = f"{name}_x_{vname}"
            src, _ = tla_module(mod, model, trans)
            open(os.path.join(outdir, mod + ".tla"), "w").write(src)
            key = label.split(" ")[0]
            open(os.path.join(outdir, mod + ".cfg"), "w").write(
                f"INIT Init\nNEXT Next\nCONSTRAINT Bound\nCHECK_DEADLOCK FALSE\nINVARIANT {key}\n")
            jobs.append((mod, key, True))
    return jobs


def check_tla(outdir, jar, jobs):
    ok = True
    for mod, key, expect_violation in jobs:
        r = subprocess.run(["java", "-XX:+UseParallelGC", "-cp", jar, "tlc2.TLC", "-workers", "auto",
                            "-metadir", os.path.join(outdir, "states", mod), "-config", mod + ".cfg", mod + ".tla"],
                           capture_output=True, text=True, cwd=outdir)
        text = r.stdout + r.stderr
        violated = "Invariant" in text and "is violated" in text
        finished = "Model checking completed. No error has been found." in text
        m = re.search(r"(\d+) distinct states found", text)
        states = m.group(1) if m else "?"
        if expect_violation:
            good = violated
            print(f"  {'VIOLATED' if violated else 'NOT VIOLATED':13} {mod} ({key})")
        else:
            good = finished
            print(f"  {'PASS' if finished else 'FAIL':13} {mod}: {states} distinct states")
        if not good:
            print(text[-1500:])
        ok &= good
    return ok


# ---------------------------------------------------------------- Lean 4
def lean_prop(e, sorts):
    """Translate a boolean s-expression to a Lean Prop."""
    if isinstance(e, str):
        if e == "true":
            return "True"
        if e == "false":
            return "False"
        return f"({e} = true)"
    op = e[0]
    if op == "and":
        return "(" + " ∧ ".join(lean_prop(x, sorts) for x in e[1:]) + ")"
    if op == "or":
        return "(" + " ∨ ".join(lean_prop(x, sorts) for x in e[1:]) + ")"
    if op == "not":
        return f"(¬ {lean_prop(e[1], sorts)})"
    if op == "=>":
        return f"({lean_prop(e[1], sorts)} → {lean_prop(e[2], sorts)})"
    if op == "ite":
        return (f"(({lean_prop(e[1], sorts)} → {lean_prop(e[2], sorts)}) ∧ "
                f"((¬ {lean_prop(e[1], sorts)}) → {lean_prop(e[3], sorts)}))")
    if op in ("=", "<", "<=", ">", ">="):
        sym = {"<=": "≤", ">=": "≥"}.get(op, op)
        return f"({lean_int(e[1], sorts)} {sym} {lean_int(e[2], sorts)})"
    raise ValueError(op)


def lean_int(e, sorts):
    if isinstance(e, str):
        return f"({e} : Int)" if is_int(e) else e
    op = e[0]
    if op in ("+", "-"):
        return "(" + f" {op} ".join(lean_int(x, sorts) for x in e[1:]) + ")"
    if op == "ite":
        return f"(if {lean_prop(e[1], sorts)} then {lean_int(e[2], sorts)} else {lean_int(e[3], sorts)})"
    raise ValueError(op)


LEAN_TACTIC = "  intros\n  simp only [Bool.not_eq_true] at *\n  grind"


def lean_file(model, tactic):
    vs = dict(model["vars"], **model["const"])
    conj = list(model["safety"].values()) + list(model["aux"])
    inv = ["and"] + [parse(c) for c in conj] if len(conj) > 1 else parse(conj[0])
    binders = " ".join(f"({v} : {'Bool' if s == 'Bool' else 'Int'})" for v, s in vs.items())
    ns = "Scout." + model["id"].capitalize()
    out = [f"/-! SCOUT: {model['title']}.", "",
           "Generated by export.py from the transition system in scout_smt.py.",
           "Each theorem is one inductive-invariant obligation; the invariant is the",
           "conjunction of the safety properties and the auxiliary facts. -/", "",
           f"namespace {ns}", "", "set_option maxHeartbeats 2000000", ""]
    out += ["/-- Safety properties (the first conjuncts) and auxiliary invariant. -/",
            f"def Inv {binders} : Prop :=\n  {lean_prop(inv, vs)}", ""]
    args = " ".join(vs)
    out += [f"theorem init {binders}\n    (hInit : {lean_prop(parse(model['init']), vs)}) :\n    Inv {args} := by",
            "  unfold Inv", tactic, ""]
    n = 1
    for tn, (params, guard, upd) in model["trans"].items():
        pb = " ".join(f"({p} : {'Bool' if s == 'Bool' else 'Int'})" for p, s in params.items())
        env = {v: parse(e) for v, e in upd.items()}
        post = lean_prop(subst(inv, env), dict(vs, **params))
        out += [f"/-- The invariant is preserved by `{tn}`. -/",
                f"theorem step_{tn} {binders} {pb}\n    (hInv : Inv {args})\n"
                f"    (hGuard : {lean_prop(parse(guard), dict(vs, **params))}) :\n    {post} := by",
                "  unfold Inv at hInv", tactic, ""]
        n += 1
    for label, prop in model["safety"].items():
        key = label.split(" ")[0]
        out += [f"/-- {label}. -/",
                f"theorem safe_{key} {binders}\n    (hInv : Inv {args}) :\n    {lean_prop(parse(prop), vs)} := by",
                "  unfold Inv at hInv", tactic, ""]
        n += 1
    out += [f"end {ns}", ""]
    return "\n".join(out), n


def write_lean(outdir, tactic=LEAN_TACTIC):
    os.makedirs(outdir, exist_ok=True)
    files = []
    for model in M.MODELS:
        src, n = lean_file(model, tactic)
        path = os.path.join(outdir, "Scout" + model["id"].capitalize() + ".lean")
        open(path, "w").write(src)
        files.append((path, n))
    return files


def check_lean(files):
    ok = True
    for path, n in files:
        r = subprocess.run(["lean", path], capture_output=True, text=True)
        text = (r.stdout + r.stderr).strip()
        good = r.returncode == 0 and "error" not in text and "sorry" not in text
        print(f"  {'CHECKED' if good else 'FAILED':8} {os.path.basename(path)}: {n} theorems")
        if not good:
            print(text[:3000])
        ok &= good
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check-lean", action="store_true")
    ap.add_argument("--check-tla", metavar="JAR")
    a = ap.parse_args()
    files = write_lean(os.path.join(HERE, "lean"))
    print(f"wrote {len(files)} Lean files ({sum(n for _, n in files)} theorems)")
    jobs = []
    if a.check_tla:
        jobs = write_tla(os.path.join(HERE, "tla"))
        print(f"wrote {len(jobs)} TLA+ modules")
    ok = True
    if a.check_lean:
        print("\nLean 4 kernel check")
        ok &= check_lean(files)
    if a.check_tla:
        print("\nTLC model checking")
        ok &= check_tla(os.path.join(HERE, "tla"), a.check_tla, jobs)
    print("\nRESULT:", "all checks passed" if ok else "FAILURE")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
