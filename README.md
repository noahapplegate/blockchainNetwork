# blockchainNetwork
A class simulating a blockchain network based on the Bitcoin network.

* [cryptoNetwork](#cryptoNetwork)
    * [Wallet](#Wallet)
    * [FullNode](#FullNode)
    * [MinerNode](#MinerNode)
    * [Network](#Network)
* [blockchain](#blockchain)
   * [Block](#Block)
   * [Blockchain](#Blockchain)

## `cryptoNetwork`

### `Wallet`

Facilitates the spending and receiving of coins

#### Attributes

    secret_key : bytes
        The Wallet's secret key. Used to sign Transactions sent by this Wallet.
        
    public_key : bytes
        The Wallet's public key. Acts as an address for other Wallet's to
        reference when sending coin to this Wallet.
        
    balance : int
        Total amount of coin held by the Wallet.
        
    node : FullNode
        The node in the cryptocurrency network this wallet is connected to.
        
    wallet_utxo_set: Deque[(txid: bytes, output_ind: int, amount: int)]
        List of UTXOs and their corresponding amounts owned by this wallet.
        UTXOs are referenced by a triple containing their Transaction ID,
        the output index, and the amount of coin within them.
        
    last_block_queried: bytes
        The last Block this Wallet has read in the Blockchain. 
        Used when updating this Wallet as a point to stop reading for new 
        Transactions involving this Wallet.
#### Methods
    __init__()
        Generates a secret key and public key for this Wallet. Initializes
        the balance, and UTXO set. Must call connect_to_network before
        other Wallet methods can be used.
        
    send(outputs: List[TXOutput], fee: int)
        Sends coin in amounts and locations specified by outputs which
        is a list of TXOutputs.
        
    update_wallet()
        Queries the associated FullNode for updated Blocks. Checks
        Transactions on the block to update UTXOs and balance.
        
    connect_to_network(network: Network)
        Connects the Wallet to a random node in the Network. This node is then
        responsible for broadcasting Transactions specified by this Wallet.
        
### `FullNode`

A Node on the network used to validate new Blocks and maintain a record
of Transactions in a Blockchain

#### Attributes

    node_blockchain : Blockchain
        This node's copy of the Blockchain.
        
    local_txs : List[Transaction]
        Transactions heard by Wallets connected to this node not yet broadcast
        to the rest of the Network
        
    mempool : List[Transaction]
        Transactions heard by this node from other nodes on the network.
        Transactions are validated before being placed in the mempool.
        
    utxo_set : Dict[bytes, TXOutput]
        Maps encodings of Transaction headers and output indices to TXOutputs.
        Outputs in this set have not been spent.
        
#### Methods
    copy(node: FullNode)
        Used to initialize subsequent FullNodes and gives them copies
        of an existing FullNode's Blockchain.
        
    listen_for_blocks(new_block: Block)
        Validates the new Block heard from the network and if it is valid adds
        it to the Blockchain. Updates the UTXO set and mempool to reflect
        confirmation of this Block.
        
    validate_block(new_block: Block) -> bool
        Validates all Transactions in the new Block, checks that the Block has
        a valid proof-of-work, and checks the Block's previous hash is correct.
        
    listen_for_transactions(transactions: List[Transaction])
        Checks if Transactions heard from the Network are valid and if so adds
        them to the Node's mempool to await confirmation.
        
    validate_tx(tx: Transaction) -> bool
        Determines if a Transaction is valid. Checks for double spends,
        over spends, invalid signatures, invalid Transaction data.
        
    update_utxo_set(new_block: Block)
        Given a new valid Block added to this node's Blockchain, checks all
        Transactions in the Block and removes used inputs from the UTXO set and
        adds new outputs to the UTXO set.
        
    update_mempool(new_block: Block)
        Given a new valid Block added to this node's Blockchain, checks all
        Transactions in the Block to see if they are in the node's mempool.
        If so, these Transactions are removed.

### `MinerNode(FullNode)`

A Node on the network that creates new blocks and provides proof-of-work.

#### Attributes

    miner_public_key : bytes
        Miner's public key to be used for outputs of coinbase Transactions
        and fees.
        
    new_block : Block
        A newly mined Block waiting to be broadcast to the rest of the network.
        
    MinerNode.difficulty : int
        Number of zeros that a Block header must start with for the Block to be
        considered as having a valid proof-of-work.
        
#### Methods

    __init__(miner_public_key)
        Initializes the miner_public_key.
        
    create_new_block()
        Collect transactions from the mempool and add them to a new Block.
        Then compute a valid proof-of-work for that Block and set it as
        the next Block to broadcast.
        
### `Network`

Network of FullNodes and MinerNodes that constitute the decentralized
cryptocurrency network

#### Attributes

    nodes : List
        List of FullNodes and MinerNodes participating on the Network.
        
    miner_indices : List[int]
        List of indices into the nodes list that specified which nodes are
        MinerNodes.
        
#### Methods

    add_full_node()
        Creates a new FullNode on the network.
        
    add_miner_node(public_key: bytes)
        Creates a new MinerNode on the network. Sends its block rewards and
        fees to the specified public key.
        
    copy_network_data(new_node)
        Used on new nodes to copy the Blockchain, UTXO set, and mempools of
        currently running nodes.
        
    transaction_broadcast(broadcaster)
        Broadcasts Transactions specified by the Wallets connected to the
        broadcaster node.
        
    block_broadcast(broadcaster: MinerNode)
        Broadcasts the newly mined Block from the specified broadcaster node.     

## `blockchain`

### `Block`

Represents a block in the Blockchain.

#### Attributes

    time_stamp : datetime.datetime
        The time of the Block's creation.
        
    transactions : List[Transaction]
        Transaction data being stored in the Block.
        
    previous_hash : bytes
        Hash of the previous Block in the Blockchain.
        
    nonce : int
        Guessed by miners creating the Block's proof-of-work.
        
    difficulty : int
        Number of zero hex digits that must appear at the beginning of the
        block header to be considered a valid proof of work.
        
#### Methods

    __init__(transactions: List[Transaction])
        Initializes the Block with a List of Transactions, a timestamp,
        and a nonce of zero.
        Meaningful values for the nonce and hash come when the block is mined
        and for previous_hash when added to the Blockchain.
        
    copy() -> Block
        Returns a copy of this block.
        
    generate_hash() -> bytes
        Creates a unique Block header by hashing the time the block was created
        along with transaction data, previous hash, and a nonce confirming
        proof-of-work.
        
    has_proof_of_work() -> bool
        Checks the Block's hash to see if the number of zeros at the beginning
        of the hash is greater than or equal to the difficulty score.
        
    print_block()
        Prints the Block header, time stamp, previous block header, and
        Transaction data. Formats everything as hex.

### `Blockchain`

#### Attributes

    blocks : List[Block]
        The list of Blocks in the Blockchain
        
#### Methods

    __init__()
        Creates a new Blockchain containing only the Genesis Block
    copy() -> Blockchain
        Returns a copy of this Blockchain
    append_block(block)
        Appends a copy of the argument block to the Blockchain.
    print_blockchain():
        Prints each Block in the Blockchain
