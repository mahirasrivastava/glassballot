"""Election layer: maps one-to-one onto the six synopsis modules.

    M1 registration     -> authority.py
    M2 ballot casting   -> voter.py, ballot.py
    M3 ballot proof     -> ballot.py (uses crypto.sigma / crypto.proofs)
    M4 bulletin board   -> bulletin_board.py
    M5 tallying         -> tally.py, service.py
    M6 public audit     -> verifier.py
"""
