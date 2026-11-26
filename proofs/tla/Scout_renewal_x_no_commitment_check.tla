---- MODULE Scout_renewal_x_no_commitment_check ----
EXTENDS Integers

VARIABLES gen, reserved, resOp, closed, saved, savedGen, savedOp, savedCt, commitTok, pend, inflight, presTok, provTok, exchDone, lapsed, count0, c0, c0ct, d0, d0ct, badTok, badReplay, badClosed, g0
vars == <<gen, reserved, resOp, closed, saved, savedGen, savedOp, savedCt, commitTok, pend, inflight, presTok, provTok, exchDone, lapsed, count0, c0, c0ct, d0, d0ct, badTok, badReplay, badClosed, g0>>

Init ==
  /\ gen \in 0..1
  /\ reserved \in BOOLEAN
  /\ resOp \in 0..1
  /\ closed \in BOOLEAN
  /\ saved \in BOOLEAN
  /\ savedGen \in 0..1
  /\ savedOp \in 0..1
  /\ savedCt \in 0..1
  /\ commitTok \in 0..1
  /\ pend \in BOOLEAN
  /\ inflight \in BOOLEAN
  /\ presTok \in 0..1
  /\ provTok \in 0..1
  /\ exchDone \in BOOLEAN
  /\ lapsed \in BOOLEAN
  /\ count0 \in 0..1
  /\ c0 \in BOOLEAN
  /\ c0ct \in 0..1
  /\ d0 \in BOOLEAN
  /\ d0ct \in 0..1
  /\ badTok \in BOOLEAN
  /\ badReplay \in BOOLEAN
  /\ badClosed \in BOOLEAN
  /\ g0 \in 0..2
  /\ ((gen = 0) /\ ~(reserved) /\ ~(closed) /\ ~(saved) /\ ~(pend) /\ ~(inflight) /\ (commitTok = provTok) /\ ~(exchDone) /\ ~(lapsed) /\ (count0 = 0) /\ ~(c0) /\ ~(d0) /\ ~(badTok) /\ ~(badReplay) /\ ~(badClosed) /\ (g0 >= 0))

Reserve ==
  \E op \in 0..1, t \in 0..1 :
    /\ (~(closed) /\ ~(reserved))
    /\ reserved' = TRUE
    /\ resOp' = op
    /\ pend' = TRUE
    /\ presTok' = t
    /\ saved' = FALSE
    /\ UNCHANGED <<gen, closed, savedGen, savedOp, savedCt, commitTok, inflight, provTok, exchDone, lapsed, count0, c0, c0ct, d0, d0ct, badTok, badReplay, badClosed, g0>>

Exchange ==
  \E newTok \in 0..1 :
    /\ pend
    /\ pend' = FALSE
    /\ inflight' = TRUE
    /\ exchDone' = TRUE
    /\ count0' = (count0 + (IF (gen = g0) THEN 1 ELSE 0))
    /\ badTok' = (badTok \/ ~((presTok = provTok)))
    /\ provTok' = newTok
    /\ UNCHANGED <<gen, reserved, resOp, closed, saved, savedGen, savedOp, savedCt, commitTok, presTok, lapsed, c0, c0ct, d0, d0ct, badReplay, badClosed, g0>>

Commit ==
  \E ct \in 0..1 :
    /\ (inflight /\ reserved /\ ~(closed))
    /\ inflight' = FALSE
    /\ reserved' = FALSE
    /\ exchDone' = FALSE
    /\ lapsed' = FALSE
    /\ saved' = TRUE
    /\ savedGen' = gen
    /\ savedOp' = resOp
    /\ savedCt' = ct
    /\ commitTok' = provTok
    /\ gen' = (gen + 1)
    /\ c0' = (c0 \/ (gen = g0))
    /\ c0ct' = (IF (gen = g0) THEN ct ELSE c0ct)
    /\ UNCHANGED <<resOp, closed, pend, presTok, provTok, count0, d0, d0ct, badTok, badReplay, badClosed, g0>>

Replay ==
  \E op \in 0..1 :
    /\ (~(closed) /\ saved /\ (savedOp = op))
    /\ d0' = (d0 \/ (savedGen = g0))
    /\ d0ct' = (IF (savedGen = g0) THEN savedCt ELSE d0ct)
    /\ badReplay' = (badReplay \/ ((savedGen = g0) /\ (~((savedCt = c0ct)) \/ (d0 /\ ~((d0ct = savedCt))))))
    /\ badClosed' = (badClosed \/ closed)
    /\ UNCHANGED <<gen, reserved, resOp, closed, saved, savedGen, savedOp, savedCt, commitTok, pend, inflight, presTok, provTok, exchDone, lapsed, count0, c0, c0ct, badTok, g0>>

Crash ==
  /\ TRUE
  /\ pend' = FALSE
  /\ inflight' = FALSE
  /\ UNCHANGED <<gen, reserved, resOp, closed, saved, savedGen, savedOp, savedCt, commitTok, presTok, provTok, exchDone, lapsed, count0, c0, c0ct, d0, d0ct, badTok, badReplay, badClosed, g0>>

Close ==
  /\ TRUE
  /\ closed' = TRUE
  /\ saved' = FALSE
  /\ UNCHANGED <<gen, reserved, resOp, savedGen, savedOp, savedCt, commitTok, pend, inflight, presTok, provTok, exchDone, lapsed, count0, c0, c0ct, d0, d0ct, badTok, badReplay, badClosed, g0>>

Expire ==
  /\ saved
  /\ saved' = FALSE
  /\ lapsed' = TRUE
  /\ UNCHANGED <<gen, reserved, resOp, closed, savedGen, savedOp, savedCt, commitTok, pend, inflight, presTok, provTok, exchDone, count0, c0, c0ct, d0, d0ct, badTok, badReplay, badClosed, g0>>

Next == Reserve \/ Exchange \/ Commit \/ Replay \/ Crash \/ Close \/ Expire

Bound == gen \in 0..3 /\ count0 \in 0..3

\* S1 at most one provider exchange per generation
S1 == (count0 =< 1)

\* S2 client credential used only with the root's current token
S2 == ~(badTok)

\* S3 every delivery for a generation is the committed ciphertext
S3 == ~(badReplay)

\* S4 no reply released after closure
S4 == ~(badClosed)

\* S5 a committed reply stays retrievable until retired, lapsed or closed
S5 == ((c0 /\ (gen = (g0 + 1)) /\ ~(reserved) /\ ~(closed) /\ ~(lapsed)) => (saved /\ (savedGen = g0) /\ (savedCt = c0ct)))

====
