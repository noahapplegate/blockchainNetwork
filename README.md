# blockchainNetwork
A class simulating a blockchain network based on the Bitcoin network.

# `blockchainNetwork`

## `Wallet`

Facilitates the spending and receiving of coins

### Attributes

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
### Methods
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
