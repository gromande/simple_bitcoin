import binascii
import random
import hashlib
import json
import numpy as np
import Crypto
import Crypto.Random
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

def sha256(message):
    return hashlib.sha256(message.encode('ascii')).hexdigest()

def dumb_hash(message):
    """
    Returns an hexadecimal hash
    """
    return sha256(message)

class Wallet(object):
    """
    A Wallet is a private/public key par
    """
    def __init__(self):
        random_gen = Crypto.Random.new().read
        self._private_key = RSA.generate(1024, random_gen)
        self._public_key = self._private_key.publickey()
        self._signer = PKCS1_v1_5.new(self._private_key)

    @property
    def address(self):
        """We take a shortcut and say address is public key"""
        return binascii.hexlify(self._public_key.exportKey(format='DER')).decode('ascii')

    def sign(self, message):
        """Sign a message with this wallet"""
        h = SHA.new(message.encode('utf8'))
        return binascii.hexlify(self._signer.sign(h)).decode('ascii')

def verify_signature(wallet_address, message, signature):
    """
    Check that the provded `signature` corresponds to `message`
    signed by the wallet at `wallet_address`
    """
    pubkey = RSA.importKey(binascii.unhexlify(wallet_address))
    verifier = PKCS1_v1_5.new(pubkey)
    h = SHA.new(message.encode('utf8'))
    return verifier.verify(h, binascii.unhexlify(signature))

w1 = Wallet()
sigature = w1.sign('foobar')
assert verify_signature(w1.address, 'foobar', sigature)
assert not verify_signature(w1.address, 'rogue message', sigature)

class TransactionInput(object):
    """
    An input for a transaction. This points to an output of another transaction
    """
    def __init__(self, transaction, output_index):
        self.transaction = transaction
        self.output_index = output_index
        assert 0 <= self.output_index < len(transaction.outputs)

    def to_dict(self):
        d = {
            'transaction': self.transaction.hash(),
            'output_index': self.output_index
        }
        return d

    @property
    def parent_output(self):
        return self.transaction.outputs[self.output_index]

class TransactionOutput(object):
    """
    An output for a transaction. This specifies an amount and a recipient (wallet)
    """
    def __init__(self, recipient_address, amount):
        self.recipient = recipient_address
        self.amount = amount

    def to_dict(self):
        d = {
            'recipient_address': self.recipient,
            'amount': self.amount
        }
        return d

def compute_fee(inputs, outputs):
    """
    Compute the transaction fee by computing the difference between
    total input and total output
    """
    total_in = sum(i.transaction.outputs[i.output_index].amount for i in inputs)
    total_out = sum(o.amount for o in outputs)
    assert total_out <= total_in, "Invalid transaction with out(%f) > in(%f)" % (total_out, total_in)
    return total_in - total_out

class Transaction(object):
    def __init__(self, wallet, inputs, outputs):
        """
        Create a transaction spending money fron the provided wallet
        """
        self.inputs = inputs
        self.outputs = outputs
        self.fee = compute_fee(inputs, outputs)
        self.signature = wallet.sign(json.dumps(self.to_dict(include_signature=False)))

    def to_dict(self, include_signature=True):
        d = {
            "inputs": list(map(TransactionInput.to_dict, self.inputs)),
            "outputs": list(map(TransactionOutput.to_dict, self.outputs)),
            "fee": self.fee
        }
        if include_signature:
            d["signature"] = self.signature
        return d

    def hash(self):
        return dumb_hash(json.dumps(self.to_dict()))

class GenesisTransaction(Transaction):
    """
    This is the first transaction which is a special transaction
    with no input and 25 bitcoins output
    """
    def __init__(self, recipient_address, amount=25):
        self.inputs = []
        self.outputs = [
            TransactionOutput(recipient_address, amount)
        ]
        self.fee = 0
        self.signature = 'genesis'

    def to_dict(self, include_signature=False):
        assert not include_signature, "Cannot include signature of genesis transaction"
        return super().to_dict(include_signature=False)

alice = Wallet()
bob = Wallet()

t1 = GenesisTransaction(alice.address)
t2 = Transaction(
    alice,
    [TransactionInput(t1, 0)],
    [TransactionOutput(bob.address, 2.0), TransactionOutput(alice.address, 22.0)]
)
assert np.abs(t2.fee - 1.0) < 1e-5
