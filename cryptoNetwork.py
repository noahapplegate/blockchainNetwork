from blockchain import Blockchain, Block
from transaction import Transaction, TXInput, TXOutput
from Crypto.PublicKey import RSA
from typing import List, Deque
from collections import deque
import copy


class Wallet:
    """
    Facilitates the spending and receiving of coins
    ...
    Attributes
    ----------
    secret_key : bytes
        The Wallet's secret key
    public_key : bytes
        The Wallet's public key. Acts as an address for other Wallet's to
        reference when sending coin to this Wallet
    balance : int
        Total amount of coin held by the Wallet
    node : FullNode
        The node in the cryptocurrency network this wallet is connected to
    wallet_utxo_set: Deque[(txid: bytes, output_ind: int, amount: int)]
        List of UTXOs and their corresponding amounts owned by this wallet
        UTXOs are referenced by a triple containing their Transaction ID,
        the output index, and the amount of coin within them
    last_block_queried: bytes
        Block header of the last Block in the Blockchain the last time this
        Wallet queried its associated FullNode


    Methods
    -------
    __init__(node: FullNode)
        Generates a secret key and public key for this Wallet. Initializes
        the balance, UTXO set, and connects the Wallet to the given FullNode.
    send(outputs: List[TXOutput], fee: int)
        Sends coin in amounts and locations specified by outputs which
        is a list of TXOutputs
    update_wallet()
        Queries the associated FullNode for updated Blocks. Checks
        Transactions on the block to update UTXOs and balance.
    """
    def __init__(self, node: 'FullNode'):
        # Generate secret key, public key pair
        keypair = RSA.generate(2048)

        self.secret_key = keypair.export_key()
        self.public_key = keypair.publickey().export_key()
        self.balance = 0
        self.node = node
        self.wallet_utxo_set = deque()
        self.last_block_queried = node.node_blockchain.blocks[0].generate_hash()
        self.update_wallet()

    def send(self, outputs: List[TXOutput], fee: int):
        # Get the total amount being sent
        total_out = fee
        for tx_out in outputs:
            total_out += tx_out.amount

        # Make sure we are not overdrawing and update the balance
        if total_out > self.balance:
            return

        inputs = []
        total_in = 0
        while total_in < total_out:
            # Get next UTXO owned by this Wallet
            cur_utxo = self.wallet_utxo_set.popleft()
            txid = cur_utxo[0]
            output_ind = cur_utxo[1]
            utxo_amt = cur_utxo[2]

            # Create a new TXInput and add it to list of inputs used in this TX
            new_in = TXInput(txid, output_ind)
            inputs.append(new_in)

            # Update the total amount used in inputs so far
            total_in += utxo_amt

        self.balance -= total_in
        # Calculate change and send it to this Wallet
        if total_in > total_out:
            change = TXOutput(total_in - total_out, self.public_key)
            outputs.append(change)

        # Create a Transaction, sign it, and send it to the connected FullNode
        new_tx = Transaction(inputs, outputs)
        new_tx.sign(self.secret_key, self.public_key)
        self.node.local_txs.append(new_tx)

    def update_wallet(self):
        updated_chain = self.node.node_blockchain.blocks
        i = -1
        while updated_chain[i].generate_hash() != self.last_block_queried:
            # Scan this block for TXs sending this Wallet coins
            for tx in updated_chain[i].transactions:
                for k in range(len(tx.outputs)):
                    txout = tx.outputs[k]
                    if txout.owner == self.public_key:
                        # This output is sending this Wallet coins
                        # Update the utxo set and the balance
                        self.wallet_utxo_set.append((tx.get_txid(), k, txout.amount))
                        self.balance += txout.amount

            # Move the next block in the chain
            i -= 1

        # We have scanned all Blocks not previously seen in the chain. No more to update
        self.last_block_queried = updated_chain[-1].generate_hash()


class FullNode:
    """
    A Node on the network used to validate new Blocks and maintain a record
    of Transactions in a Blockchain
    ...
    Attributes
    ----------
    node_blockchain : Blockchain
        This node's copy of the Blockchain
    unvalidated_txs : List[Transaction]
        List of Transactions to be broadcast to MinerNodes

    Methods
    -------
    __init__()
        Used to initialize a new FullNode
    copy(node: FullNode)
        Used to initialize subsequent FullNodes and gives them copies
        of an existing FullNode's Blockchain
    listen_for_blocks(mined_blocks: List[Block])
        Verifies transactions and proof-of-work new Blocks confirmed by
        miners and adds it to the node's blockchain.
    validate_tx(tx: Transaction) -> bool
        Determines if a Transaction is valid. Checks for double spends,
        over spends, invalid signatures, invalid Transaction data.
    """
    def __init__(self):
        self.node_blockchain = Blockchain()
        self.local_txs = []
        self.mempool = []
        self.utxo_set = dict()

    def copy(self):
        return copy.deepcopy(self)

    def listen_for_blocks(self, new_block: Block):
        # If the new Block is valid, add it the Blockchain
        # Update this node's UTXO set and Mempool
        if self.validate_block(new_block):
            self.node_blockchain.append_block(new_block)
            self.update_utxo_set(new_block)
            self.update_mempool(new_block)

    def validate_tx(self, tx: Transaction) -> bool:
        # Verify the TX data has a valid signature
        if not tx.verify_signature():
            return False

        # Check all inputs used in the TX are in the UTXO set and that they
        # are owned by the sender of the TX
        total_in = 0
        for txin in tx.inputs:
            input_key = txin.prev_tx + str(txin.output_ind).encode()
            if input_key not in self.utxo_set or self.utxo_set[input_key].owner != tx.sender_public_key:
                return False
            else:
                total_in += self.utxo_set[input_key].amount

        # Check that input amount is >= the output amount
        total_out = 0
        for txout in tx.outputs:
            total_out += txout.amount
        if total_in < total_out:
            return False

        return True

    def listen_for_transactions(self, transactions: List[Transaction]):
        # Add valid transactions to the mempool
        for tx in transactions:
            if self.validate_tx(tx):
                self.mempool.append(tx)

    def update_utxo_set(self, new_block: Block):
        # Inputs used in Block TXs are no longer UTXOs
        # Outputs in Block are now UTXOs
        # Ignore the coinbase transaction
        for i in range(len(new_block.transactions)-1):
            tx = new_block.transactions[i]
            # Ignore coinbase input
            for txin in tx.inputs:
                utxo_key = txin.prev_tx + str(txin.output_ind).encode()
                del self.utxo_set[utxo_key]

            out_ind = 0
            for txout in tx.outputs:
                utxo_key = tx.get_txid() + str(out_ind).encode()
                self.utxo_set[utxo_key] = TXOutput(txout.amount, txout.owner)
                out_ind += 1

        # Add Coinbase output to UTXO set
        cb_tx = new_block.transactions[-1]
        cb_out = cb_tx.outputs[0]
        cb_key = cb_tx.get_txid() + str(0).encode()
        self.utxo_set[cb_key] = TXOutput(cb_out.amount, cb_out.owner)

    def update_mempool(self, new_block: Block):
        # If a TX in this node's mempool is in the new Block, remove it
        for new_tx in new_block.transactions:
            for tx in self.mempool:
                if new_tx.get_txid() == tx.get_txid():
                    self.mempool.remove(tx)

    def validate_block(self, new_block: Block):
        # Validate TXs included in the new block (ignore the coinbase TX)
        for i in range(len(new_block.transactions)-1):
            tx = new_block.transactions[i]
            if not self.validate_tx(tx):
                return False

        # Check that the new block has a valid proof-of-work
        if not new_block.has_proof_of_work():
            return False

        # Block is valid
        return True


class MinerNode(FullNode):
    """
    A Node on the network that creates new blocks and provides proof-of-work
    ...
    Attributes
    ----------
    miner_public_key : bytes
        Miner's public key to be used for outputs of coinbase
        Transactions and fees
    new_blocks : List[Block]
        List of Blocks created by the miner to be broadcast back to FullNodes
        for confirmation
    MinerNode.difficulty : int
        Number of zeros that must start the header of a Block
        to be considered valid

    Methods
    -------
    __init__(miner_public_key)
        Initializes the miner_public_key and an empty mempool
    copy()
        Return a copy of this node
    listen_for_transactions(transactions: List[Transactions])
        Listen for Transactions being broadcast and add them to the mempool
        to await confirmation
    create_new_block()
        Collect transactions from the mempool and add them to a new Block

    """
    difficulty = 2

    def __init__(self):
        FullNode.__init__(self)
        self.miner_public_key = bytes()
        self.new_block = None

    def create_new_block(self):
        # Add all Transactions from the mempool to the new Block
        new_block = Block(self.mempool, MinerNode.difficulty)

        # Collect fees and block reward as a new TX
        total_in = 0
        total_out = 0
        for tx in new_block.transactions:
            for txin in tx.inputs:
                total_in += self.utxo_set[txin.prev_tx + str(txin.output_ind).encode()].amount
            for txout in tx.outputs:
                total_out += txout.amount
        total_fees = total_in - total_out
        block_reward = 10

        # Create coinbase TX
        coinbase_out = TXOutput(total_fees + block_reward, self.miner_public_key)
        coinbase_in = TXInput(str(len(self.node_blockchain.blocks)).encode(), 0)
        coinbase_tx = Transaction([coinbase_in], [coinbase_out])
        new_block.transactions.append(coinbase_tx)

        # Set previous Block
        new_block.previous_hash = self.node_blockchain.blocks[-1].generate_hash()

        # Generate a valid proof of work for the new Block
        while not new_block.has_proof_of_work():
            new_block.nonce += 1

        # Prepare to broadcast the block
        self.new_block = new_block


class Network:
    """
    Network of BasicNodes and MinerNodes that constitute the decentralized
    cryptocurrency network
    ...
    Attributes
    ----------
    full_nodes : List[FullNode]
        Nodes participating on the network by maintaining the Blockchain
        and creating transactions
    miner_nodes : List[MinerNode]
        Nodes participating on the network by validating transactions,
        creating new blocks, and providing proof-of-work for new blocks

    Methods
    -------
    __init__()
        Initialize new Network with one FullNode and one MinerNode
    add_full_node()
        Creates a new basic node on the network
    add_miner_node()
        Creates a new miner node on the network
    transaction_broadcast()
        Broadcasts verified transactions from FullNodes to MinerNodes
    block_broadcast()
        Broadcasts blocks from MinerNodes to FullNodes
    """
    def __init__(self):
        self.full_nodes = []
        self.miner_nodes = []

    def add_full_node(self):
        new_node = FullNode()
        # If there are already nodes in the network, copy their data
        if len(self.full_nodes) > 0:
            new_node = self.full_nodes[0].copy()
        self.full_nodes.append(new_node)

    def add_miner_node(self):
        new_node = MinerNode()
        # If there are already nodes in the network, copy their data
        if len(self.miner_nodes) > 0:
            new_node.mempool = copy.deepcopy(self.miner_nodes[0].mempool)
            new_node.utxo_set = copy.deepcopy(self.miner_nodes[0].utxo_set)
        self.miner_nodes.append(new_node)

    def transaction_broadcast(self, broadcaster):
        # For each FullNode, send the node's unvalidated TXs to every
        # MinerNode in the Network to be added to a new Block
        for full_node in self.full_nodes:
            full_node.listen_for_transactions(broadcaster.local_txs)
        for miner_node in self.miner_nodes:
            miner_node.listen_for_transactions(broadcaster.local_txs)

        broadcaster.local_txs = []

    def block_broadcast(self, broadcaster):
        # For each MinerNode, send the node's new Blocks to every
        # FullNode in the Network for confirmation
        for full_node in self.full_nodes:
            full_node.listen_for_blocks(broadcaster.new_block)
        for miner_node in self.miner_nodes:
            miner_node.listen_for_blocks(broadcaster.new_block)

        broadcaster.new_block = None
