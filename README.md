# SCOUT proofs

Machine-checked proofs and models for SCOUT, a split-custody, session-bound credential renewal protocol for human-authorized AI agents.

Companion to "SCOUT: Split-Custody, Session-Bound Credential Renewal for Human-Authorized AI Agents".

| Path | What it is | How to run |
|---|---|---|
| `scout_smt.py` | Inductive-invariant proofs (Z3) for the session, delivery, renewal, assertion-mediated renewal, teardown and authorization models; bounded model checking of 26 broken variants; delegation rule; custody closure | `python3 scout_smt.py` (needs `z3` on PATH; 4.15.4 used) |
| `obligations/` | The 41 generated SMT-LIB 2 proof obligations; each must be `unsat` | `z3 obligations/<file>.smt2` or any SMT-LIB solver |
| `results.txt` | Output of `scout_smt.py` | |
| `export.py`, `lean/` | The same six models exported to Lean 4: 63 theorems (41 invariant obligations, 22 safety properties), checked by the Lean kernel | `python3 export.py --check-lean` (needs `lean`; 4.36.0 used) |
| `symbolic/gen.py` | Generates and runs eight ProVerif models of delivery, renewal and revocation (three SCOUT scenarios, three broken variants, two baselines) and checks each result against its expected value | `python3 symbolic/gen.py` (needs `proverif`; 2.05 used) |
| `symbolic/gen_assertion.py` | Six two-phase ProVerif models: broker compromise at renewal, and assertion-mediated renewal with shared or per-grant client identity | `python3 symbolic/gen_assertion.py` |
| `symbolic/*.pv`, `*.log`, `results*.txt` | Generated models, full ProVerif output, summary | |
| `bounded/model_check.py` | Exhaustive breadth-first exploration of three finite abstractions with nine negative controls | `python3 bounded/model_check.py --output-dir bounded` |
| `bounded/wire_codec.py`, `test_wire_codec.py`, `wire-vectors.json`, `wire-format.md` | Reference encoder and checker for a typed wire profile, 26 tests | `cd bounded && python3 -m unittest test_wire_codec` (needs the `cryptography` package) |

Every script exits 0 only if all proofs pass and every broken variant is caught.
These are proofs about models of the protocol, not about an implementation; see Section 7.5 of the paper.

## Run everything

```sh
python3 scout_smt.py                         # Z3: 41 induction obligations, 26 broken variants
python3 export.py --check-lean                # Lean 4: 63 theorems
python3 symbolic/gen.py                      # ProVerif: 8 scenarios
python3 symbolic/gen_assertion.py            # ProVerif: 6 two-phase scenarios
python3 bounded/model_check.py --output-dir bounded
(cd bounded && python3 -m unittest test_wire_codec)
```

## How to cite

This work may be used for any purpose under CC BY 4.0. If you use it, cite the paper:

> Algimantas Krasauskas. *SCOUT: Split-Custody, Session-Bound Credential Renewal for Human-Authorized AI Agents*. November 2026.

GitHub's "Cite this repository" button gives the same reference in BibTeX and APA form. The DOI will be added here once the paper is published.

## Licence

[Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/) (CC BY 4.0); see `LICENSE`. You may use, share and adapt this work for any purpose, provided you cite the paper.
