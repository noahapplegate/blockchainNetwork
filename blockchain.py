import datetime
from Crypto.Hash import SHA256
from transaction import Transaction
from typing import List
import copy


class Block:
    """
    Represents a block in the Blockchain
    ...
    Attributes
    ----------
    time_stamp : datetime.datetime
        The time of the Block's creation
    transactions : List[Transaction]
        Transaction data being stored in the Block
    previous_hash : bytes
        Hash of the previous Block in the Blockchain
    nonce : int
        Guessed by miners creating the Block's proof-of-work
    difficulty : int
        Number of zero hex digits that must appear at the beginning of the
        block header to be considered a valid proof of work

    Methods
    -------
    __init__(transactions: List[Transaction])
        Initializes the Block with a List of Transactions, a timestamp,
        and a nonce of zero.
        Meaningful values for the nonce and hash come when the block is mined
        and for previous_hash when added to the Blockchain.
    copy() -> Block
        Returns a copy of this block
    generate_hash() -> bytes
        Creates a unique Block header by hashing the time the block was created
        along with transaction data, previous hash, and a nonce confirming
        proof-of-work
    has_proof_of_work() -> bool
        Checks the Block's hash to see if the number of zeros at the beginning
        of the hash is greater than or equal to the difficulty score

    """
    def __init__(self, transactions: List[Transaction], difficulty: int):
        self.transactions = copy.deepcopy(transactions)
        self.previous_hash = bytes()
        self.time_stamp = datetime.datetime.now()
        self.nonce = 0
        self.difficulty = difficulty

    def copy(self) -> 'Block':
        return copy.deepcopy(self)

    def generate_hash(self) -> bytes:
        block_hash = SHA256.new()

        # Hash timestamp, Transaction data, previous hash, and nonce
        block_hash.update(str(self.time_stamp).encode())
        for tx in self.transactions:
            block_hash.update(tx.get_txid())
        block_hash.update(self.previous_hash)
        block_hash.update(str(self.nonce).encode())

        return block_hash.digest()

    def has_proof_of_work(self):
        # Get relevant digits in Block hash as a string
        first_n = self.generate_hash().hex()[:self.difficulty]
        return first_n == '0' * self.difficulty


class Blockchain:
    """
    List of Blocks comprising the Blockchain
    ...
    Attributes
    ----------
    blocks : List[Block]
        The list of Blocks in the Blockchain

    Methods
    -------
    __init__()
        Creates a new Blockchain containing only the Genesis Block
    copy() -> Blockchain
        Returns a copy of this Blockchain
    append_block(block)
        Appends a copy of the argument block to the Blockchain. Sets the
        Block's previous hash to the last Block in the chain.
    """
    def __init__(self):
        # Genesis Block has no Transactions, previous_hash of all 0s
        genesis_block = Block([])
        zeros = '0' * 64
        zero_header = bytes.fromhex(zeros)
        genesis_block.previous_hash = zero_header
        self.blocks = [genesis_block]

    def copy(self):
        return copy.deepcopy(self)

    def append_block(self, block: Block):
        block.previous_hash = self.blocks[-1].generate_hash()
        self.blocks.append(block.copy())
