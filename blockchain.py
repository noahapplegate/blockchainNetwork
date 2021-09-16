import datetime
from Crypto.Hash import SHA256


class Block:
    """
    Represents a block in the Blockchain
    ...
    Attributes
    ----------
    time_stamp : str
        The time of the Block's creation
    transactions : List[Transaction]
        Transaction data being stored in the Block
    previous_hash : Crypto.Hash.SHA256
        Hash of the previous Block in the Blockchain
    nonce : int
        Guessed by miners creating the Block's proof-of-work
    hash : Crypto.Hash.SHA256
        Unique hash resulting from hashing timestamp, transaction data,
        and nonce

    Methods
    -------
    __init__(transactions, previous_hash)
        Initializes the Block with a List of Transactions and the hash
        of the previous Block in the Blockchain
    generate_hash()
        Creates a unique Block header by hashing the time the block was
        created along with transaction data, previous hash, and a nonce
        confirming proof-of-work
    """
    def __init__(self, transactions, previous_hash):
        self.time_stamp = datetime.datetime.now()
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.nonce = 0
        self.hash = self.generate_hash()

    def generate_hash(self):
        block_hash = SHA256.new()
        block_hash.update(self.time_stamp)
        for tx in self.transactions:
            block_hash.update(tx.tx_id)
        block_hash.update(self.previous_hash)
        block_hash.update(str(self.nonce).encode())
        return block_hash


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
        Initializes the Blockchain with the genesis block
        No Transactions in the block, previous header of 0
    append_block(block)
        Appends a new Block to the end of the chain
    """
    def __init__(self):
        # Add the genesis block
        self.blocks = [Block([], 0)]

    def append_block(self, block):
        self.blocks.append(block)
