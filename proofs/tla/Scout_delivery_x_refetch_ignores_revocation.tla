---- MODULE Scout_delivery_x_refetch_ignores_revocation ----
EXTENDS Integers

VARIABLES status, delivered, fp, resp, rel, relResp, badDiff, badRev
vars == <<status, delivered, fp, resp, rel, relResp, badDiff, badRev>>

Init ==
  /\ status \in 0..1
  /\ delivered \in BOOLEAN
  /\ fp \in 0..1
  /\ resp \in 0..1
  /\ rel \in BOOLEAN
  /\ relResp \in 0..1
  /\ badDiff \in BOOLEAN
  /\ badRev \in BOOLEAN
  /\ ((status = 0) /\ ~(delivered) /\ ~(rel) /\ ~(badDiff) /\ ~(badRev))

Fetch ==
  \E req \in 0..1, r \in 0..1 :
    /\ ((status = 0) /\ ~(delivered))
    /\ rel' = TRUE
    /\ relResp' = r
    /\ badDiff' = (badDiff \/ (rel /\ ~((relResp = r))))
    /\ badRev' = (badRev \/ (status = 2))
    /\ delivered' = TRUE
    /\ fp' = req
    /\ resp' = r
    /\ status' = 1

Refetch ==
  \E req \in 0..1 :
    /\ (delivered /\ (req = fp))
    /\ rel' = TRUE
    /\ relResp' = resp
    /\ badDiff' = (badDiff \/ (rel /\ ~((relResp = resp))))
    /\ badRev' = (badRev \/ (status = 2))
    /\ UNCHANGED <<status, delivered, fp, resp>>

FetchOther ==
  \E req \in 0..1 :
    /\ ((status = 1) /\ delivered /\ ~((req = fp)))
    /\ status' = 2
    /\ UNCHANGED <<delivered, fp, resp, rel, relResp, badDiff, badRev>>

Revoke ==
  /\ TRUE
  /\ status' = 2
  /\ UNCHANGED <<delivered, fp, resp, rel, relResp, badDiff, badRev>>

Next == Fetch \/ Refetch \/ FetchOther \/ Revoke

Bound == TRUE

\* D1 every released response is the first one
D1 == ~(badDiff)

\* D2 nothing is released after revocation
D2 == ~(badRev)

====
