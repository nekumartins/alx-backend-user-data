#!/usr/bin/env python3
"""
Encryption Module
"""
import bcrypt
from bcrypt import hashpw


def hash_password(password: str) -> bytes:
    """
    Returns a hashed password
    """
    bc = password.encode()
    hashed = hashpw(bc, bcrypt.gensalt())
    return hashed


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Return:
    bool
    """
    return bcrypt.checkpw(password.encode(), hashed_password)
