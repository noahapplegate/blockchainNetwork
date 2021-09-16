from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15


class TXOutput:
    """
    Output of a transaction (who the coin is going to + how much)
    ...
    Attributes
    ----------
    amount : int
        Amount of coin being spent in this output
    owner : Crypto.PublicKey.RSA
        Key object that identifies the new owner of this coin

    Methods
    -------
    __init__(amount, owner)
        Initializes the TXOutput with the amount being sent and the
        public key of the recipient
    """
    def __init__(self, amount, owner):
        self.amount = amount
        self.owner = owner


class TXInput:
    """
    Input of a coin transaction (where the coin is coming from)
    ...
    Attributes
    ----------
    prev_tx : bytes
        ID of the Transaction where the output being spent resides
    output_ind : int
        Index within the specified Transaction of the output being spent

    Methods
    -------
    __init__(prev_tx, output_ind)
        Initializes the TXInput with the previous Transaction header and
        the index of the output being spent within that Transaction
    """
    def __init__(self, prev_tx, output_ind):
        self.prev_tx = prev_tx
        self.output_ind = output_ind


class Transaction:
    """
    Represents coin transactions (receiving and sending)
    ...
    Attributes
    ----------
    inputs : List[TXInput]
        UTXOs being spent in the transaction
    outputs : List[TXOutput]
        Describes how the coin is being spent
    tx_id : Crypto.Hash.SHA256
        A unique identifier of this transaction
    sender_public_key : Crypto.PublicKey.RSA
        Public key of the created of this transaction. Used to verify
        the signature on the transaction.
    signature : Crypto.Signature.pkcs1_15
        Digital signature created using the sender's secret key

    Methods
    -------
    __init__(inputs)
        Initializes the inputs and outputs of the transaction and
        generates a new transaction id

    verify_signature()
        Uses the public key of the sender to verify this transaction was
        created by the correct sender

    """
    def __init__(self, inputs, outputs, sender_key_pair):
        self.inputs = inputs
        self.outputs = outputs
        self.sender_public_key = sender_key_pair.publickey().export_key()

        # Generate Transaction ID
        # SHA256 Hash of inputs
        self.tx_id = SHA256.new()
        for tx_in in inputs:
            self.tx_id.update(tx_in.prev_tx + str(tx_in.output_ind).encode())

        # Sign the transaction input data
        self.signature = pkcs1_15.new(sender_key_pair).sign(self.tx_id)

    def verify_signature(self) -> bool:
        try:
            pkcs1_15.new(self.sender_public_key).verify(self.tx_id, self.signature)
            return True
        except (ValueError, TypeError):
            return False


