import logging
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
        digest = dumb_hash(message + nonce)
        if digest.startswith(prefix):
            return nonce, i
        i += 1

nonce, niters = mine('42', difficulty=1)
print("Took %d iterations to find nonce: %s" % (niters, nonce))
nonce, niters = mine('42', difficulty=3)
print("Took %d iterations to find nonce: %s" % (niters, nonce))

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

def compute_balance(wallet_address, transactions):
    """
    Given an address and a list of transactions, computes the wallet balance
    """
    balance = 0
    for t in transactions:
        for txin in t.inputs:
            if txin.parent_output.recipient == wallet_address:
                balance -= txin.parent_output.amount
        for txout in t.outputs:
            if txout.recipient == wallet_address:
                balance += txout.amount
    return balance

def verify_transaction(transaction):
    """
    Verify that the transaction is valid.
    We need to verify two things:
        - That all the inputs of the transaction belong to the same wallet
        - That the transaction is signed by the onwer of the said wallet
    """
    tx_message = json.dumps(transaction.to_dict(include_signature=False))
    if isinstance(transaction, GenesisTransaction):
        # TODO: We should probably be more carefull about validating genesis
        # transactions
        return True

    #Verify input transactions
    for tx in transaction.inputs:
        if not  verify_transaction(tx.transaction):
            logging.error("Invalid parent transaction")
            return False

    # Verify a single wallet ownes all the inputs
    first_input_address = transaction.inputs[0].parent_output.recipient
    for txin in transaction.inputs[1:]:
        if txin.parent_output.recipient != first_input_address:
            logging.error("Transaction inputs belong to multiple wallets (%s and %s)" %
                          (txin.parent_output.recipient, first_input_address))
            return False

    if not verify_signature(first_input_address, tx_message, transaction.signature):
        logging.error("Invalid transaction signature")
        return False

    #Call compute_fee here to validate the fee
    compute_fee(transaction.inputs, transaction.outputs)

    return True

alice = Wallet()
bob = Wallet()
walter = Wallet()

# This gives 25 coins to Alice
t1 = GenesisTransaction(alice.address)

# Of those 25, Alice will spend
# Alice -- 5 --> Bob
#       -- 15 --> Alice
#       -- 5 --> Walter
t2 = Transaction(
    alice,
    [TransactionInput(t1, 0)],
    [TransactionOutput(bob.address, 5.0), TransactionOutput(alice.address, 15.0),
     TransactionOutput(walter.address, 5.0)]
)

# Walter -- 5 --> Bob
t3 = Transaction(
    walter,
    [TransactionInput(t2, 2)],
    [TransactionOutput(bob.address, 5.0)]
)

# Bob -- 8 --> Walter
#     -- 1 --> Bob
#        1 fee
t4 = Transaction(
    bob,
    [TransactionInput(t2, 0), TransactionInput(t3, 0)],
    [TransactionOutput(walter.address, 8.0), TransactionOutput(bob.address, 1.0)]
)

assert verify_transaction(t1)
assert verify_transaction(t2)
assert verify_transaction(t3)
assert verify_transaction(t4)

transactions = [t1, t2, t3, t4]

assert np.abs(t4.fee - 1.0) < 1e-5

print("Alice has %.02f coins" % compute_balance(alice.address, transactions))
print("Bob has %.02f coins" % compute_balance(bob.address, transactions))
print("Walter has %.02f coins" % compute_balance(walter.address, transactions))

# This is invalid because bob is trying to spend Alice's money
t5 = Transaction(
    bob,
    [TransactionInput(t1, 0)],
    [TransactionOutput(walter.address, 10.0)]
)

assert not verify_transaction(t5)

BLOCK_INCENTIVE = 25 # The coins miners get for mining a block
DIFFICULTY = 2

def compute_total_fee(transactions):
    """Return the total fee for the set of transactions"""
    return sum(t.fee for t in transactions)

class Block(object):
    def __init__(self, transactions, ancestor, miner_address, skip_verif=False):
        """
        Args:
            transactions: the list of transactions to include in the block
            ancestor: the previous block
            miner_address: the miner's wallet address.
        """
        reward = compute_total_fee(transactions) + BLOCK_INCENTIVE
        self.transactions = [GenesisTransaction(miner_address, amount=reward)] + transactions
        self.ancestor = ancestor

        if not skip_verif:
            assert all(map(verify_transaction, transactions))

        json_block = json.dumps(self.to_dict(include_hash=False))
        self.nonce, _ = mine(json_block, DIFFICULTY)
        self.hash = dumb_hash(json_block + self.nonce)

    def fee(self):
        """Return transaction fee for this block"""
        return compute_total_fee(self.transactions)

    def to_dict(self, include_hash=True):
        d = {
            "transactions": list(map(Transaction.to_dict, self.transactions)),
            "previous_block": self.ancestor.hash,
        }
        if include_hash:
            d["nonce"] = self.nonce
            d["hash"] = self.hash
        return d

class GenesisBlock(Block):
    """
    The genesis block is the first block in the chain.
    It is the only block with no ancestor
    """
    def __init__(self, miner_address):
        super(GenesisBlock, self).__init__(transactions=[], ancestor=None,
                                           miner_address=miner_address)

    def to_dict(self, include_hash=True):
        d = {
            "transactions": [],
            "genesis_block": True,
        }
        if include_hash:
            d["nonce"] = self.nonce
            d["hash"] = self.hash
        return d

def verify_block(block, genesis_block, used_outputs=None):
    """
    Verifies that a block is valid:
        - The hash starts with the required amount of ones
        - The same transaction output isn't used twice
        - All transactions are valid
        - The first transaction in the bloc is a genesis transactions with
        BLOCK_INCENTIVE + total_fee

    Args:
        block: the block to validate
        genesis_block: the genesis block (this needs to be shared with everybody)
        used_outputs: list of outputs used in transactions for all blocks above this one
    """
    if used_outputs is None:
        used_outputs = set()

    # Verify hash
    prefix = '1' * DIFFICULTY
    if not block.hash.startswith(prefix):
        logging.error("Block hash (%s) doesn't start with prefix %s" %
                      (block.hash, prefix))
        return False

    # Verify transactions
    if not all(map(verify_transaction, block.transactions)):
        return False

    # Verify that transactions in this block don't use already spent outputs
    for transaction in block.transactions:
        for i in transaction.inputs:
            if i.parent_output in used_outputs:
                logging.error("Transaction uses and already used output: &s" %
                              json.dumps(i.parent_output.to_dict()))
                return False
            used_outputs.add(i.parent_output)

    # Verify ancestors up to genesis block
    if not (block.hash == genesis_block.hash):
        if not verify_block(block.ancestor, genesis_block, used_outputs):
            logging.error("Failed to validate ancestor block")
            return False

    # Verify the first transaction is the miner's reward
    tx0 = block.transactions[0]
    if not isinstance(tx0, GenesisTransaction):
        logging.error("Tx 0 is not a GenesisTransaction")
        return False
    if not len(tx0.outputs) == 1:
        logging.error("Tx0 does't have exactly one output")
        return False

    reward = compute_total_fee(block.transactions[1:]) + BLOCK_INCENTIVE
    if not tx0.outputs[0].amount == reward:
        logging.error("Invalid amount in Tx0: %d, expected %d" %
                      (tx0.outputs[0].amount, reward))
        return False

    # Only the first transaction shall be a genesis
    for i, tx in enumerate(block.transactions[1:]):
        if isinstance(tx, GenesisTransaction):
            logging.error("GenesisTransaction (hash=%s) at index %d != 0" %
                          (tx.hash(), i))
            return False

    return True

def collect_transactions(block, genesis_block):
    """Recursively collect transactions in `block` and all of its ancestors"""
    # Important: COPY block.transactions
    transactions = [] + block.transactions
    if block.hash != genesis_block.hash:
        transactions += collect_transactions(block.ancestor, genesis_block)
    return transactions

genesis_block = GenesisBlock(miner_address=alice.address)
print("genesis_block : %s with fee=%s" % (genesis_block.hash, str(genesis_block.fee())))

t1 = genesis_block.transactions[0]
block1 = Block([t2], ancestor=genesis_block, miner_address=walter.address)
print("block1   : %s  with fee=%s" % (block1.hash, str(block1.fee())))
assert verify_block(block1, genesis_block)

block2 = Block([t3, t4], ancestor=block1, miner_address=walter.address)
print("block2   : %s  with fee=%s" % (block2.hash, str(block2.fee())))
assert verify_block(block2, genesis_block)

transactions = collect_transactions(block2, genesis_block)
print("Alice has %.02f coins" % compute_balance(alice.address, transactions))
print("Bob has %.02f coins" % compute_balance(bob.address, transactions))
print("Walter has %.02f coins" % compute_balance(walter.address, transactions))
