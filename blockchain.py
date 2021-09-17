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
    hash : bytes
        Unique hash resulting from hashing timestamp, transaction data,
        and nonce

    Methods
    -------
    __init__(transactions: List[Transaction], previous_hash: bytes)
        Initializes the Block with a List of Transactions and the hash
        of the previous Block in the Blockchain
    copy() -> Block
        Returns a copy of this block
    generate_hash() -> bytes
        Creates a unique Block header by hashing the time the block was created
        along with transaction data, previous hash, and a nonce confirming
        proof-of-work
    """
    def __init__(self, transactions: List[Transaction], previous_hash: bytes):
        self.transactions = copy.deepcopy(transactions)
        self.previous_hash = previous_hash
        self.time_stamp = datetime.datetime.now()
        self.nonce = 0
        self.hash = self.generate_hash()

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
        Appends a copy of the argument block to the Blockchain
    """
    def __init__(self):
        # Genesis Block has no Transactions, previous_hash of all 0s
        zeros = '0' * 64
        init_prev_header = bytes.fromhex(zeros)
        self.blocks = [Block([], init_prev_header)]

    def copy(self):
        return copy.deepcopy(self)

    def append_block(self, block: Block):
        self.blocks.append(block.copy())
