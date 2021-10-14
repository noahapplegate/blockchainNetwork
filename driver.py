from cryptoNetwork import Network, Wallet

# Create a Wallet, and a Network
# Add a FullNode and a MinerNode onto the Network
# Have the MinerNode send Block rewards to the new Wallet
wallet1 = Wallet()
test_net = Network()
test_net.add_full_node()
test_net.add_miner_node(wallet1.public_key)

# Mine three blocks and broadcast them on the network
# No Transactions at this point so do not need to worry
# About broadcasting Transactions
test_net.nodes[1].create_new_block()
test_net.block_broadcast(test_net.nodes[1])

test_net.nodes[1].create_new_block()
test_net.block_broadcast(test_net.nodes[1])

test_net.nodes[1].create_new_block()
test_net.block_broadcast(test_net.nodes[1])

# Create another Wallet and connect both to the Network
wallet1.connect_to_network(test_net)
wallet2 = Wallet()
wallet2.connect_to_network(test_net)

# Wallet 1 has 30 coin from mining 3 blocks
# Have wallet1 send wallet2 17 coin in two transactions with a fee of 2 for the miner
# Broadcast this transaction to the network
outputs = [(12, wallet2.public_key), (5, wallet2.public_key)]
wallet1.send(outputs, 2)
test_net.transaction_broadcast(wallet1.node)

# Add another miner, send rewards to wallet2
test_net.add_miner_node(wallet2.public_key)

# Miner another block with the second miner and broadcast the new block to the network
test_net.nodes[2].create_new_block()
test_net.block_broadcast(test_net.nodes[2])

# Have both wallets query the network for new coin sent to them
wallet1.update_wallet()
wallet2.update_wallet()

test_net.nodes[0].node_blockchain.print_blockchain()
print()
print("Wallet1")
print("balance: ", wallet1.balance)
print("Wallet2")
print("Balance: ", wallet2.balance)
