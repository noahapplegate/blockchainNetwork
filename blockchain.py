import datetime
from Crypto.Hash import SHA256
from transaction import Transaction


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
    __init__(transactions, previous_hash)
        Initializes the Block with a List of Transactions and the hash
        of the previous Block in the Blockchain
    __init__(block)
        Copy constructor
    generate_hash() -> bytes
        Creates a unique Block header by hashing the time the block was created
        along with transaction data, previous hash, and a nonce confirming
        proof-of-work
    """
    def __init__(self, transactions, previous_hash):
        # Deep copy of transactions
        self.transactions = []
        for tx in transactions:
            tx_copy = \
                Transaction(tx.inputs, tx.outputs, tx.sender_private_key, tx.sender_public_key)
            self.transactions.append(tx_copy)

        self.previous_hash = previous_hash
        self.time_stamp = datetime.datetime.now()
        self.nonce = 0
        self.hash = self.generate_hash()

    def __init__(self, block):
        # Deep copy of transactions
        self.transactions = []
        for tx in block.transactions:
            tx_copy = \
                Transaction(tx.inputs, tx.outputs, tx.sender_private_key, tx.sender_public_key)
            self.transactions.append(tx_copy)

        self.previous_hash = block.previous_hash
        self.time_stamp = block.time_stamp
        self.nonce = block.nonce
        self.hash = block.hash

    def generate_hash(self) -> bytes:
        block_hash = SHA256.new()
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
        Initializes the Blockchain with the genesis block
        No Transactions in the block, previous header of 0
    __init__(existing_chain)
        Initializes the Blockchain with the contents of the existing_chain
    append_block(block)
        Appends a new Block to the end of the chain
    """
    def __init__(self):
        # Add the genesis block
        self.blocks = [Block([], 0)]

    def __init__(self, existing_chain):
        # Deep copy of blocks
        self.blocks = []
        for block in existing_chain:
            self.blocks.append(Block(block))

    def append_block(self, block):
        self.blocks.append(block)
