from blockchain import Blockchain, Block
from transaction import Transaction, TXInput, TXOutput


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
    wallet_utxo_set: List[(txid: bytes, output_ind: int, amount: int)]
        List of UTXOs and their corresponding amounts owned by this wallet
        UTXOs are referenced by a triple containing their Transaction ID,
        the output index, and the amount of coin within them


    Methods
    -------
    __init__(node: FullNode)
        Generates a secret key and public key for this Wallet. Initializes
        the balance, UTXO set, and connects the Wallet to the given FullNode.
    send(outputs: List[TXOutput])
        Sends coin in amounts and locations specified by outputs which
        is a list of TXOutputs
    updateWallet()
        Queries the associated FullNode for updated Blocks. Checks
        Transactions on the block to update UTXOs and balance.
    """


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
        List of validated Transactions to be broadcast to miners
    utxo_set : Dict[bytes, bytes]
        Maps Transaction ID's of UTXOs to the public key that owns them

    Methods
    -------
    __init__()
        Used to initialize a new FullNode
    copy(node: FullNode)
        Used to initialize subsequent FullNodes and gives them copies
        of an existing FullNode's Blockchain and UTXO set
    validate_tx(tx: Transaction)
        Determines if a Transaction is valid. Checks for double spends,
        over spends, invalid signatures, invalid Transaction data.
    listen_for_blocks(block: Block):
        Verifies transactions and proof-of-work on a new Block confirmed by
        miners and adds it to the node's blockchain. Updates the UTXO set.
    """


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

    Methods
    -------
    __init__(miner_public_key)
        Initializes the miner_public_key and an empty mempool
    listen_for_transactions(transactions: List[Transactions])
        Listen for Transactions being broadcast and add them to the mempool
        to await confirmation
    create_new_block()
        Collect transactions from the mempool and add them to a new Block
    proof_of_work(block)
        Perform a proof-of-work for the specified block
    """


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



