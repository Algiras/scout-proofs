---- MODULE Scout_assertion_x_issue_after_closure ----
EXTENDS Integers

VARIABLES gen, reserved, resOp, expired, exchanged, closed, live, commitDig, runnerDig, count0, badIssue, badLate, g0
vars == <<gen, reserved, resOp, expired, exchanged, closed, live, commitDig, runnerDig, count0, badIssue, badLate, g0>>

Init ==
  /\ gen \in 0..1
  /\ reserved \in BOOLEAN
  /\ resOp \in 0..1
  /\ expired \in BOOLEAN
  /\ exchanged \in BOOLEAN
  /\ closed \in BOOLEAN
  /\ live \in BOOLEAN
  /\ commitDig \in 0..1
  /\ runnerDig \in 0..1
  /\ count0 \in 0..1
  /\ badIssue \in BOOLEAN
  /\ badLate \in BOOLEAN
  /\ g0 \in 0..2
  /\ ((gen = 0) /\ ~(reserved) /\ ~(expired) /\ ~(exchanged) /\ ~(closed) /\ live /\ (commitDig = runnerDig) /\ (count0 = 0) /\ ~(badIssue) /\ ~(badLate) /\ (g0 >= 0))

ReserveIssue ==
  \E op \in 0..1 :
    /\ (live /\ ~(reserved) /\ (runnerDig = commitDig))
    /\ reserved' = TRUE
    /\ resOp' = op
    /\ expired' = FALSE
    /\ exchanged' = FALSE
    /\ count0' = (count0 + (IF (gen = g0) THEN 1 ELSE 0))
    /\ badIssue' = (badIssue \/ closed \/ ~(live) \/ ~((runnerDig = commitDig)))
    /\ UNCHANGED <<gen, closed, live, commitDig, runnerDig, badLate, g0>>

Retry ==
  \E op \in 0..1 :
    /\ (reserved /\ (op = resOp) /\ ~(expired) /\ ~(closed))
    /\ badLate' = (badLate \/ expired \/ closed)
    /\ UNCHANGED <<gen, reserved, resOp, expired, exchanged, closed, live, commitDig, runnerDig, count0, badIssue, g0>>

AssertionExpires ==
  /\ reserved
  /\ expired' = TRUE
  /\ UNCHANGED <<gen, reserved, resOp, exchanged, closed, live, commitDig, runnerDig, count0, badIssue, badLate, g0>>

RunnerExchange ==
  \E newDig \in 0..1 :
    /\ (reserved /\ ~(expired) /\ ~(exchanged))
    /\ exchanged' = TRUE
    /\ runnerDig' = newDig
    /\ UNCHANGED <<gen, reserved, resOp, expired, closed, live, commitDig, count0, badIssue, badLate, g0>>

Complete ==
  \E r \in 0..1 :
    /\ (reserved /\ ~(closed))
    /\ reserved' = FALSE
    /\ commitDig' = r
    /\ gen' = (gen + 1)
    /\ UNCHANGED <<resOp, expired, exchanged, closed, live, runnerDig, count0, badIssue, badLate, g0>>

Close ==
  /\ TRUE
  /\ closed' = TRUE
  /\ UNCHANGED <<gen, reserved, resOp, expired, exchanged, live, commitDig, runnerDig, count0, badIssue, badLate, g0>>

SessionEnds ==
  /\ TRUE
  /\ live' = FALSE
  /\ UNCHANGED <<gen, reserved, resOp, expired, exchanged, closed, commitDig, runnerDig, count0, badIssue, badLate, g0>>

Next == ReserveIssue \/ Retry \/ AssertionExpires \/ RunnerExchange \/ Complete \/ Close \/ SessionEnds

Bound == gen \in 0..3 /\ count0 \in 0..3

\* M1 at most one client assertion per generation
M1 == (count0 =< 1)

\* M2 assertions only for a live, open session whose committed digest matches the held token
M2 == ~(badIssue)

\* M3 no assertion is returned after expiry or closure
M3 == ~(badLate)

====
