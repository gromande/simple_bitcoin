import hashlib
import random
import string
import json
import binascii
import numpy as np
import pandas as pd
#import pylab as pl
import logging

def sha256(message):
    return hashlib.sha256(message.encode('ascii')).hexdigest()

def dum_hash(message):
    """
    Returns an hexadecimal hash
    """
    return sha256(message)

def mine(message, difficulty=1):
    """
    Given an input string, will return a nonce such that
    hash(string + nonce) starts with `difficulty` ones

    Returns: (nonce, niters)
        nonce: the found nonce
        niters: number of iterations required to find the nonce
    """
    assert difficulty >= 1, "Difficulty of 0 is not possible"
    i = 0
    prefix = '1' * difficulty
    while True:
        nonce = str(i)
        digest = dum_hash(message + nonce)
        if digest.startswith(prefix):
            return nonce, i
        i += 1

nonce, niters = mine('42', difficulty=1)
print("Took %d iterations to find nonce: %s" % (niters, nonce))
nonce, niters = mine('42', difficulty=3)
print("Took %d iterations to find nonce: %s" % (niters, nonce))
