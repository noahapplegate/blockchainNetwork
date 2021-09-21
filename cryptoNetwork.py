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
        self.last_block_queried = node.node_blockchain.blocks[-1].generate_hash()

    def send(self, outputs: List[TXOutput], fee: int):
        # Get the total amount being sent
        total_out = fee
        for tx_out in outputs:
            total_out += tx_out.amount

        # Make sure we are not overdrawing and update the balance
        if total_out > self.balance:
            return
        else:
            self.balance -= total_out

        # Add temporary dummy outputs to account for the fee and accessing past end of list
        outputs.append(TXOutput(fee, bytes()))
        outputs.append(TXOutput(0, bytes()))

        # Get UTXOs to fulfill the requested amount to send
        out_it = iter(outputs)
        cur_out = next(out_it)
        cur_out_amt = cur_out.amount
        inputs = []
        remainders = []
        while total_out > 0:
            # Get the next UTXO, update the total output remaining to satisfy
            cur_utxo = self.wallet_utxo_set.popleft()
            utxo_amt = cur_utxo[2]

            # Create a new input using the current UTXO and add it to list of inputs
            txid = cur_utxo[0]
            output_ind = cur_utxo[1]
            new_input = TXInput(txid, output_ind)
            inputs.append(new_input)

            if utxo_amt < cur_out_amt:
                # UTXO does not have enough coin to satisfy this output
                # We have satisfied utxo_amt of the cur_out_amt remaining
                cur_out_amt -= utxo_amt
                total_out -= utxo_amt
            else:
                # UTXO can be used to fully satisfy this output
                if utxo_amt > cur_out_amt:
                    # UTXO has more coin that required. Use it fully and send
                    # the remainder back to ourselves
                    utxo_remainder = utxo_amt - cur_out_amt
                    remainder_output = TXOutput(utxo_remainder, self.public_key)
                    remainders.append(remainder_output)

                total_out -= cur_out_amt
                # This output is satisfied, get the next one
                cur_out = next(out_it)
                cur_out_amt = cur_out.amount

        # Remove dummy outputs and append remainders
        outputs.pop()
        outputs.pop()
        outputs.extend(remainders)

        # Create a Transaction, sign it, and send it to the connected FullNode
        new_tx = Transaction(inputs, outputs)
        new_tx.sign(self.secret_key, self.public_key)
        self.node.unvalidated_txs.append(new_tx)

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
    """
    def __init__(self):
        self.node_blockchain = Blockchain()
        self.unvalidated_txs = []

    def copy(self):
        return copy.deepcopy(self)

    def listen_for_blocks(self, mined_blocks: List[Block]):
        for block in mined_blocks:
            # If the Block has a proof-of-work, add it to the Blockchain
            if block.has_proof_of_work:
                self.node_blockchain.append_block(block)


class MinerNode:
    """
    A Node on the network that creates new blocks and provides proof-of-work
    ...
    Attributes
    ----------
    mempool : List[Transactions]
        Verified Transactions waiting to be added to a Block
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
    validate_tx(tx: Transaction) -> bool
        Determines if a Transaction is valid. Checks for double spends,
        over spends, invalid signatures, invalid Transaction data.
    """
    difficulty = 2

    def __init__(self):
        self.miner_public_key = RSA.generate(2048).publickey().export_key()
        self.mempool = []
        self.new_blocks = []
        self.utxo_set = dict()

    def copy(self):
        return copy.deepcopy(self)

    def listen_for_transactions(self, transactions: List[Transaction]):
        # Add valid transactions to the mempool
        for tx in transactions:
            if self.validate_tx(tx):
                self.mempool.append(tx)

    def create_new_block(self):
        # Add all Transactions from the mempool to the new Block
        new_block = Block(self.mempool, MinerNode.difficulty)

        # Generate a valid proof of work for the new Block
        while not new_block.has_proof_of_work():
            new_block.nonce += 1

        # Inputs used in Block TXs are no longer UTXOs
        # Outputs in Block are now UTXOs
        total_in = 0
        total_out = 0
        for tx in new_block.transactions:
            for txin in tx.inputs:
                utxo_key = txin.prev_tx + str(txin.output_ind).encode()
                total_in += self.utxo_set[utxo_key].amount
                del self.utxo_set[utxo_key]

            out_ind = 0
            for txout in tx.outputs:
                total_out += txout.amount
                utxo_key = tx.get_txid() + str(out_ind).encode()
                self.utxo_set[utxo_key] = TXOutput(txout.amount, txout.owner)
                out_ind += 1

        # Collect fees and block reward as a new TX
        total_fees = total_out - total_in
        block_reward = 10
        coinbase_out = TXOutput(total_fees + block_reward, self.miner_public_key)
        coinbase_tx = Transaction([], [coinbase_out])
        new_block.transactions.append(coinbase_tx)

        # Add coinbase output to UTXO set
        cb_utxo_key = coinbase_tx.get_txid() + str(0).encode()
        self.utxo_set[cb_utxo_key] = coinbase_out

        # Add the Block to list of Blocks to be broadcast
        self.new_blocks.append(new_block)

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
            new_node = self.miner_nodes[0].copy()
        self.full_nodes.append(new_node)

    def transaction_broadcast(self):
        # For each FullNode, send the node's unvalidated TXs to every
        # MinerNode in the Network to be added to a new Block
        for full_node in self.full_nodes:
            for miner_node in self.miner_nodes:
                miner_node.listen_for_transactions(full_node.unvalidated_txs)

            # TXs have been broadcast, reset the list of validated TXs
            full_node.unvalidated_txs = []

    def block_broadcast(self):
        # For each MinerNode, send the node's new Blocks to every
        # FullNode in the Network for confirmation
        for miner_node in self.miner_nodes:
            for full_node in self.full_nodes:
                full_node.listen_for_blocks(miner_node.new_blocks)

            # This miner's new Blocks have been broadcast, reset list of new blocks
            miner_node.new_blocks = []
