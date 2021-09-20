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
    A Node on the network used to validate transactions and maintain a full
    copy of the Blockchain
    ...
    Attributes
    ----------
    node_blockchain : Blockchain
        This node's copy of the Blockchain
    unvalidated_txs : List[Transaction]
        List of Transactions that have not yet been validated
    validated_txs : List[Transaction]
        List of validated Transactions to be broadcast to MinerNodes
    utxo_set : Dict[bytes, TXOutput]
        Maps Transaction IDs and output indices of UTXOs to a TXOutput


    Methods
    -------
    __init__()
        Used to initialize a new FullNode
    copy(node: FullNode)
        Used to initialize subsequent FullNodes and gives them copies
        of an existing FullNode's Blockchain and UTXO set
    validate_tx(tx: Transaction) -> bool
        Determines if a Transaction is valid. Checks for double spends,
        over spends, invalid signatures, invalid Transaction data.
    validate_block(block: Block) -> bool
        Validates the Block's proof-of-work and Transactions
    listen_for_blocks(block: Block)
        Verifies transactions and proof-of-work on a new Block confirmed by
        miners and adds it to the node's blockchain. Updates the UTXO set.
    """
    def __init__(self, difficulty):
        self.node_blockchain = Blockchain()
        self.unvalidated_txs = []
        self.validated_txs = []
        self.utxo_set = dict()
        self.difficulty = difficulty

    def copy(self):
        return copy.deepcopy(self)

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

    def validate_block(self, block: Block) -> bool:
        # Verify the Block's proof-of-work
        if not block.has_proof_of_work():
            return False
        # Validate all TXs in the block
        for tx in block.transactions:
            if not self.validate_tx(tx):
                return False

        return True

    def listen_for_blocks(self, block: Block):
        # If the Block is invalid, it is not accepted by the Blockchain
        if not self.validate_block(block):
            return

        # Block is valid, add to Block chain
        self.node_blockchain.append_block(block)

        # Inputs used in Block TXs are no longer UTXOs
        # Outputs in Block are now UTXOs
        for tx in block.transactions:
            for txin in tx.inputs:
                utxo_key = txin.prev_tx + str(txin.output_ind).encode()
                del self.utxo_set[utxo_key]

            out_ind = 0
            for txout in tx.outputs:
                utxo_key = tx.get_txid + str(out_ind).encode()
                self.utxo_set[utxo_key] = TXOutput(txout.amount, txout.owner)


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
    difficulty : int
        Number of zeros that must start the header of a Block
        to be considered valid


    Methods
    -------
    __init__(miner_public_key)
        Initializes the miner_public_key and an empty mempool
    listen_for_transactions(transactions: List[Transactions])
        Listen for Transactions being broadcast and add them to the mempool
        to await confirmation
    create_new_block()
        Collect transactions from the mempool and add them to a new Block
    """
    difficulty = 2

    def __init__(self, miner_public_key: bytes):
        self.miner_public_key = miner_public_key
        self.mempool = []
        self.new_blocks = []

    def listen_for_transactions(self, transactions: List[Transaction]):
        # Add the new Transactions to the mempool
        self.mempool.extend(transactions)

    def create_new_block(self):
        # Add all Transactions from the mempool to the new Block
        new_block = Block(self.mempool, MinerNode.difficulty)

        # Generate a valid proof of work for the new Block
        while not new_block.has_proof_of_work():
            new_block.nonce += 1

        # Add the Block to list of Blocks to be broadcast
        self.new_blocks.append(new_block)


class Network:
    """
    Network of BasicNodes and MinerNodes that constitute the decentralized
    cryptocurrency network
    ...
    Attributes
    ----------
    basic_nodes : List[BasicNode]
        Nodes participating on the network by maintaining the Blockchain
        and creating transactions
    miner_nodes : List[MinerNode]
        Nodes participating on the network by validating transactions,
        creating new blocks, and providing proof-of-work for new blocks

    Methods
    -------
    __init__(prev_tx, output_ind)
        Initializes the TXInput with the previous Transaction header and
        the index of the output being spent within that Transaction
    add_basic_node()
        Creates a new basic node on the network
    remove_basic_node()
        Removes a basic node from the network
    add_miner()
        Creates a new miner node on the network
    remove_miner()
        Removes a miner node from the network
    transaction_broadcast()
        Broadcasts verified transactions from FullNodes to MinerNodes
    block_broadcast()
        Broadcasts blocks from MinerNodes to FullNodes
    """



