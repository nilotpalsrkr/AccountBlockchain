import hashlib
import json
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key


class Account:
    # Default balance is 100 if not sent during account creation
    # nonce is incremented once every transaction to ensure tx can't be replayed and can be ordered (similar to Ethereum)
    # private and public pem strings should be set inside __generate_key_pair
    def __init__(self, sender_id, initial_balance=100):
        self._id = sender_id
        self._initial_balance = initial_balance
        self._balance = initial_balance
        self._nonce = 0
        self._private_pem = None
        self._public_pem = None
        self.__generate_key_pair()

    @property
    def id(self):
        return self._id

    @property
    def public_key(self):
        return self._public_pem

    @property
    def balance(self):
        return self._balance

    def increase_balance(self, value):
        self._balance += value

    def decrease_balance(self, value):
        self._balance -= value

    @property
    def initialBalance(self):
        return self._initial_balance

    def __generate_key_pair(self):
        # Implement key pair generation logic
        # Convert them to pem format strings and store in the class attributes already defined
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self._private_pem = private_pem
        self._public_pem = public_pem

    def create_transaction(self, receiver_id, value, tx_metadata=''):
        nonce = self._nonce + 1
        transaction_message = {'sender': self._id, 'receiver': receiver_id, 'value': value, 'tx_metadata': tx_metadata, 'nonce': nonce}
        private_key = load_pem_private_key(self._private_pem, password=None)

        transaction_message_bytes = json.dumps(transaction_message, sort_keys=True).encode("UTF-8")
        transaction_message_base64 = hashlib.sha256(transaction_message_bytes).hexdigest()

        # Implement digital signature of the hash of the message
        signature = private_key.sign(transaction_message_base64.encode('utf-8'),
                                     padding.PSS(
                                         mgf=padding.MGF1(hashes.SHA256()),
                                         salt_length=padding.PSS.MAX_LENGTH
                                            ),
                                     hashes.SHA256()
                                     )

        # Process to verify the above signature. This isn't necessary however for the project.
        public_key = private_key.public_key()
        public_key.verify(
            signature,
            transaction_message_base64.encode('utf8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        self._nonce = nonce
        return {'message': transaction_message, 'signature': base64.b64encode(signature).decode('utf-8')}

