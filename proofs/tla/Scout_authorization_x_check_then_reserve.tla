---- MODULE Scout_authorization_x_check_then_reserve ----
EXTENDS Integers

VARIABLES stage, resEpoch, epoch, rootClosed, now, sawOpen, badRes, badDispatch, expiry
vars == <<stage, resEpoch, epoch, rootClosed, now, sawOpen, badRes, badDispatch, expiry>>

Init ==
  /\ stage \in 0..1
  /\ resEpoch \in 0..1
  /\ epoch \in 0..1
  /\ rootClosed \in BOOLEAN
  /\ now \in 0..1
  /\ sawOpen \in BOOLEAN
  /\ badRes \in BOOLEAN
  /\ badDispatch \in BOOLEAN
  /\ expiry \in 0..2
  /\ ((stage = 0) /\ (epoch = 0) /\ ~(rootClosed) /\ (now = 0) /\ ~(sawOpen) /\ ~(badRes) /\ ~(badDispatch))

Reserve ==
  /\ ((stage = 0) /\ sawOpen)
  /\ stage' = 1
  /\ resEpoch' = epoch
  /\ badRes' = (badRes \/ rootClosed \/ (now >= expiry))
  /\ UNCHANGED <<epoch, rootClosed, now, sawOpen, badDispatch, expiry>>

Dispatch ==
  /\ ((stage = 1) /\ (resEpoch = epoch) /\ ~(rootClosed) /\ (now < expiry))
  /\ stage' = 2
  /\ badDispatch' = (badDispatch \/ ~((resEpoch = epoch)))
  /\ UNCHANGED <<resEpoch, epoch, rootClosed, now, sawOpen, badRes, expiry>>

Cancel ==
  /\ ~(rootClosed)
  /\ rootClosed' = TRUE
  /\ epoch' = (epoch + 1)
  /\ UNCHANGED <<stage, resEpoch, now, sawOpen, badRes, badDispatch, expiry>>

Tick ==
  /\ TRUE
  /\ now' = (now + 1)
  /\ UNCHANGED <<stage, resEpoch, epoch, rootClosed, sawOpen, badRes, badDispatch, expiry>>

Check ==
  /\ ((stage = 0) /\ ~(rootClosed) /\ (now < expiry))
  /\ sawOpen' = TRUE
  /\ UNCHANGED <<stage, resEpoch, epoch, rootClosed, now, badRes, badDispatch, expiry>>

Next == Reserve \/ Dispatch \/ Cancel \/ Tick \/ Check

Bound == epoch \in 0..3 /\ now \in 0..3

\* A1 no reservation after closure or expiry
A1 == ~(badRes)

\* A2 no dispatch under a superseded epoch
A2 == ~(badDispatch)

====
