---- MODULE Scout_session_x_rebind_after_consent ----
EXTENDS Integers

VARIABLES st, keyPinned, pinnedKey, locked, lockedUser, anyConsent, firstUser, minted, sealKey, term, badUser, badMint
vars == <<st, keyPinned, pinnedKey, locked, lockedUser, anyConsent, firstUser, minted, sealKey, term, badUser, badMint>>

Init ==
  /\ st \in 0..1
  /\ keyPinned \in BOOLEAN
  /\ pinnedKey \in 0..1
  /\ locked \in BOOLEAN
  /\ lockedUser \in 0..1
  /\ anyConsent \in BOOLEAN
  /\ firstUser \in 0..1
  /\ minted \in BOOLEAN
  /\ sealKey \in 0..1
  /\ term \in BOOLEAN
  /\ badUser \in BOOLEAN
  /\ badMint \in BOOLEAN
  /\ ((st = 0) /\ ~(keyPinned) /\ ~(locked) /\ ~(anyConsent) /\ ~(minted) /\ ~(term) /\ ~(badUser) /\ ~(badMint))

Bind ==
  \E k \in 0..1 :
    /\ (st =< 1)
    /\ st' = 1
    /\ keyPinned' = TRUE
    /\ pinnedKey' = k
    /\ UNCHANGED <<locked, lockedUser, anyConsent, firstUser, minted, sealKey, term, badUser, badMint>>

PredeclareLock ==
  \E u \in 0..1 :
    /\ ((st =< 1) /\ ~(locked))
    /\ locked' = TRUE
    /\ lockedUser' = u
    /\ UNCHANGED <<st, keyPinned, pinnedKey, anyConsent, firstUser, minted, sealKey, term, badUser, badMint>>

Consent ==
  \E u \in 0..1, last \in BOOLEAN :
    /\ ((st = 1) /\ (~(locked) \/ (u = lockedUser)))
    /\ locked' = TRUE
    /\ lockedUser' = u
    /\ anyConsent' = TRUE
    /\ firstUser' = (IF anyConsent THEN firstUser ELSE u)
    /\ badUser' = (badUser \/ (anyConsent /\ ~((firstUser = u))))
    /\ minted' = TRUE
    /\ sealKey' = pinnedKey
    /\ badMint' = (badMint \/ ~(keyPinned))
    /\ st' = (IF last THEN 2 ELSE st)
    /\ UNCHANGED <<keyPinned, pinnedKey, term>>

Fetch ==
  /\ (st = 2)
  /\ st' = 3
  /\ UNCHANGED <<keyPinned, pinnedKey, locked, lockedUser, anyConsent, firstUser, minted, sealKey, term, badUser, badMint>>

Deny ==
  \E u \in 0..1 :
    /\ ((st =< 1) /\ (~(locked) \/ (u = lockedUser)))
    /\ st' = 4
    /\ term' = TRUE
    /\ UNCHANGED <<keyPinned, pinnedKey, locked, lockedUser, anyConsent, firstUser, minted, sealKey, badUser, badMint>>

Revoke ==
  /\ (st =< 3)
  /\ st' = 5
  /\ term' = TRUE
  /\ UNCHANGED <<keyPinned, pinnedKey, locked, lockedUser, anyConsent, firstUser, minted, sealKey, badUser, badMint>>

Expire ==
  /\ (st =< 3)
  /\ st' = 6
  /\ term' = TRUE
  /\ UNCHANGED <<keyPinned, pinnedKey, locked, lockedUser, anyConsent, firstUser, minted, sealKey, badUser, badMint>>

Next == Bind \/ PredeclareLock \/ Consent \/ Fetch \/ Deny \/ Revoke \/ Expire

Bound == TRUE

\* F1 tokens are minted only for a pinned runner key
F1 == ~(badMint)

\* F2 grants are sealed to the pinned key
F2 == (minted => (keyPinned /\ (sealKey = pinnedKey)))

\* F3 one principal per session
F3 == ~(badUser)

\* F4 terminal states are absorbing
F4 == (term => (st >= 4))

====
