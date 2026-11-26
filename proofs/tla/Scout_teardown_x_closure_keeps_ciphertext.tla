---- MODULE Scout_teardown_x_closure_keeps_ciphertext ----
EXTENDS Integers

VARIABLES closed, deleted, keyPresent, saved, bindings, reportedRevoked, provAck, badForeign, badFalseAck, badAfterClose, badNoKey
vars == <<closed, deleted, keyPresent, saved, bindings, reportedRevoked, provAck, badForeign, badFalseAck, badAfterClose, badNoKey>>

Init ==
  /\ closed \in BOOLEAN
  /\ deleted \in BOOLEAN
  /\ keyPresent \in BOOLEAN
  /\ saved \in BOOLEAN
  /\ bindings \in BOOLEAN
  /\ reportedRevoked \in BOOLEAN
  /\ provAck \in BOOLEAN
  /\ badForeign \in BOOLEAN
  /\ badFalseAck \in BOOLEAN
  /\ badAfterClose \in BOOLEAN
  /\ badNoKey \in BOOLEAN
  /\ (~(closed) /\ ~(deleted) /\ keyPresent /\ ~(saved) /\ bindings /\ ~(reportedRevoked) /\ ~(provAck) /\ ~(badForeign) /\ ~(badFalseAck) /\ ~(badAfterClose) /\ ~(badNoKey))

Revoke ==
  \E d \in BOOLEAN, resp \in 1..4 :
    /\ (keyPresent /\ d /\ (resp >= 1) /\ (resp =< 4))
    /\ badForeign' = (badForeign \/ ~(d))
    /\ badNoKey' = (badNoKey \/ ~(keyPresent))
    /\ reportedRevoked' = (resp = 1)
    /\ provAck' = (resp = 1)
    /\ badFalseAck' = (badFalseAck \/ ((resp = 1) /\ ~((resp = 1))))
    /\ UNCHANGED <<closed, deleted, keyPresent, saved, bindings, badAfterClose>>

Close ==
  /\ ~(closed)
  /\ closed' = TRUE
  /\ UNCHANGED <<deleted, keyPresent, saved, bindings, reportedRevoked, provAck, badForeign, badFalseAck, badAfterClose, badNoKey>>

Delete ==
  /\ (closed /\ ~(deleted))
  /\ deleted' = TRUE
  /\ keyPresent' = FALSE
  /\ UNCHANGED <<closed, saved, bindings, reportedRevoked, provAck, badForeign, badFalseAck, badAfterClose, badNoKey>>

Deliver ==
  /\ ~(closed)
  /\ badAfterClose' = (badAfterClose \/ closed)
  /\ UNCHANGED <<closed, deleted, keyPresent, saved, bindings, reportedRevoked, provAck, badForeign, badFalseAck, badNoKey>>

RenewAdmit ==
  /\ (~(closed) /\ bindings)
  /\ badAfterClose' = (badAfterClose \/ closed)
  /\ UNCHANGED <<closed, deleted, keyPresent, saved, bindings, reportedRevoked, provAck, badForeign, badFalseAck, badNoKey>>

RenewCommit ==
  /\ (~(closed) /\ bindings)
  /\ saved' = TRUE
  /\ badAfterClose' = (badAfterClose \/ closed)
  /\ UNCHANGED <<closed, deleted, keyPresent, bindings, reportedRevoked, provAck, badForeign, badFalseAck, badNoKey>>

Next == Revoke \/ Close \/ Delete \/ Deliver \/ RenewAdmit \/ RenewCommit

Bound == TRUE

\* T1 client credential revokes only tokens delivered in this session
T1 == ~(badForeign)

\* T2 revoked is reported only on provider acknowledgement
T2 == (~(badFalseAck) /\ (reportedRevoked => provAck))

\* T3 no delivery, renewal admission or completion after closure
T3 == ~(badAfterClose)

\* T4 records and the runner key are deleted only after closure
T4 == ((deleted => closed) /\ (~(deleted) => keyPresent))

\* T5 closure leaves no bindings or saved ciphertext
T5 == (closed => (~(saved) /\ ~(bindings)))

\* T6 revocation requests are verified against a retained runner key
T6 == ~(badNoKey)

====
