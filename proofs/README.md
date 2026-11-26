# SCOUT proofs

Companion to "SCOUT: Split-Custody, Session-Bound Credential Renewal for Human-Authorized AI Agents".

| Path | What it is | How to run |
|---|---|---|
| `scout_smt.py` | Inductive-invariant proofs (Z3) for the session, delivery, renewal, assertion-mediated renewal, teardown and authorization models; bounded model checking of 26 broken variants; delegation rule; custody closure | `python3 scout_smt.py` (needs `z3` on PATH; 4.15.4 used) |
| `obligations/` | The 41 generated SMT-LIB 2 proof obligations; each must be `unsat` | `z3 obligations/<file>.smt2` or any SMT-LIB solver |
| `results.txt` | Output of `scout_smt.py` | |
| `export.py`, `lean/` | The same six models exported to Lean 4: 63 theorems (41 invariant obligations, 22 safety properties), checked by the Lean kernel | `python3 export.py --check-lean` (needs `lean`; 4.36.0 used) |
| `export.py`, `tla/` | The same six models and their 26 broken variants exported to TLA+: 32 modules, model-checked by TLC within finite bounds | `python3 export.py --check-tla /path/to/tla2tools.jar` (needs Java; TLA+ tools 1.8.0 used) |
| `results-lean-tla.txt` | Output of the Lean and TLC run | |
| `symbolic/gen.py` | Generates and runs eight ProVerif models of delivery, renewal and revocation (three SCOUT scenarios, three broken variants, two baselines) and checks each result against its expected value | `python3 symbolic/gen.py` (needs `proverif`; 2.05 used) |
| `symbolic/gen_assertion.py` | Six two-phase ProVerif models: broker compromise at renewal, and assertion-mediated renewal with shared or per-grant client identity | `python3 symbolic/gen_assertion.py` |
| `symbolic/gen_delegation.py` | Three ProVerif models of supervised delegation with an attacker-controlled child agent | `python3 symbolic/gen_delegation.py` |
| `symbolic/*.pv`, `*.log`, `results.txt` | Generated models, full ProVerif output, summary | |

Every script exits 0 only if all proofs pass and every broken variant is caught.
These are proofs about models of the protocol, not about an implementation; see Section 7.5 of the paper.
