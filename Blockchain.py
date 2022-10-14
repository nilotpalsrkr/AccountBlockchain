import json
import hashlib
import base64

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature

from Block import Block


class Blockchain:
    # Basic blockchain init
    # Includes the chain as a list of blocks in order, pending transactions, and known accounts
    # Includes the current value of the hash target. It can be changed at any point to vary the difficulty
    # Also initiates a genesis block
    def __init__(self, hash_target):
        self._chain = []
        self._pending_transactions = []
        self._chain.append(self.__create_genesis_block())
        self._hash_target = hash_target
        self._accounts = {}

    def __str__(self):
        return f"Chain:\n{self._chain}\n\nPending Transactions: {self._pending_transactions}\n"

    @property
    def hash_target(self):
        return self._hash_target

    @hash_target.setter
    def hash_target(self, hash_target):
        self._hash_target = hash_target

    @property
    def chain(self):
        return self._chain

    # Creating the genesis block, taking arbitrary previous block hash since there is no previous block
    # Using the famous bitcoin genesis block string here :)  
    def __create_genesis_block(self):
        genesis_block = Block(0, [], 'The Times 03/Jan/2009 Chancellor on brink of second bailout for banks',
                              None, 'Genesis block using same string as bitcoin!')
        return genesis_block

    def __validate_transaction(self, transaction):
        # Serialize transaction data with keys ordered, and then convert to bytes format
        hash_string = json.dumps(transaction['message'], sort_keys=True)
        encoded_hash_string = hash_string.encode('utf-8')

        # Take sha256 hash of the serialized message, and then convert to bytes format
        message_hash = hashlib.sha256(encoded_hash_string).hexdigest()
        encoded_message_hash = message_hash.encode('utf-8')

        # Signature - Encode to bytes and then Base64 Decode to get the original signature format back 
        signature = base64.b64decode(transaction['signature'].encode('utf-8'))

        try:
            # Load the public_key object and verify the signature against the calculated hash
            sender_public_pem = self._accounts.get(transaction['message']['sender']).public_key
            sender_public_key = serialization.load_pem_public_key(sender_public_pem)
            sender_public_key.verify(
                signature,
                encoded_message_hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except InvalidSignature:
            return False

        return True

    def __process_transactions(self, transactions):
        # Appropriately transfer value from the sender to the receiver
        # For all transactions, first check that the sender has enough balance. 
        # Return False otherwise
        for valid_transaction in transactions:
            sender_account = self._accounts[valid_transaction['message']['sender']]
            receiver_account = self._accounts[valid_transaction['message']['receiver']]
            amount_to_transfer = valid_transaction['message']['value']
            sender_account.decrease_balance(amount_to_transfer)
            receiver_account.increase_balance(amount_to_transfer)
        return True

    def __validate_and_remove_invalid_transactions(self, transactions):
        for transaction in transactions:
            sender = transaction['message']['sender']
            amount_to_transfer = transaction['message']['value']
            sender_account = self._accounts[sender]

            if sender_account.balance < amount_to_transfer:
                transactions.remove(transaction)

    # Creates a new block and appends to the chain
    # Also clears the pending transactions as they are part of the new block now
    def create_new_block(self):

        # Although we are directly taking all transactions from the pending_transactions, in real blockchain
        # processing, the transactions would be taken from a pool. Here, we take the pending transactions and
        # clear away all invalid transactions. We proceed with block formation only with valid transactions.
        # The validity of a transactions is just if the sender has enough of amount to transfer.

        transactions_from_pool = self._pending_transactions
        self.__validate_and_remove_invalid_transactions(transactions=transactions_from_pool)
        new_block = Block(len(self._chain), transactions_from_pool, self._chain[-1].block_hash, self._hash_target)
        if self.__process_transactions(self._pending_transactions):
            self._chain.append(new_block)
            self._pending_transactions = []
            return new_block
        else:
            return False

    # Simple transaction with just one sender, one receiver, and one value
    # Created by the account and sent to the blockchain instance
    def add_transaction(self, transaction):
        if self.__validate_transaction(transaction):
            self._pending_transactions.append(transaction)
            return True
        else:
            print(f'ERROR: Transaction: {transaction} failed signature validation')
            return False

    def __validate_chain_hash_integrity(self):
        # Run through the whole blockchain and ensure that previous hash is actually the hash of the previous block
        # Return False otherwise
        is_genesis = True
        prev_block_hash = None
        for block in self._chain:
            if is_genesis:
                prev_block_hash = block.block_hash
                is_genesis = False
                continue
            if block.previous_block_hash != prev_block_hash:
                return False
            prev_block_hash = block.hash_block()

        return True

    def __validate_block_hash_target(self):
        # Run through the whole blockchain and ensure that block hash meets hash target criteria, and is the actual hash of the block
        # Return False otherwise
        is_genesis = True
        for block in self._chain:
            if is_genesis:
                is_genesis = False
                continue
            else:
                if int(block.hash_block(), 16) > int(block.hash_target, 16) and block.hash_block() != block.block_hash:
                    return False
        return True

    def __validate_complete_account_balances(self):
        # Run through the whole blockchain and ensure that balances never become negative from any transaction
        # Return False otherwise
        account_balance_dict = {}
        for block in self._chain:
            for transaction in block.transactions:
                sender = transaction['message']['sender']
                receiver = transaction['message']['receiver']
                amount_to_transfer = transaction['message']['value']
                sender_account = self._accounts[sender]
                receiver_account = self._accounts[receiver]
                if account_balance_dict.get(sender) is None:
                    account_balance_dict[sender] = sender_account.initialBalance
                if account_balance_dict.get(receiver) is None:
                    account_balance_dict[receiver] = receiver_account.initialBalance
                account_balance_dict[sender] -= amount_to_transfer
                account_balance_dict[receiver] += amount_to_transfer
        for account_balance_in_blockchain in self.get_account_balances():
            if account_balance_dict[account_balance_in_blockchain['id']] != account_balance_in_blockchain['balance']:
                return False
        return True

    # Blockchain validation function
    # Runs through the whole blockchain and applies appropriate validations
    def validate_blockchain(self):

        chain_intigrity_validity = self.__validate_chain_hash_integrity()
        print(f"CHAIN INTIGRITY VALIDATION  - {chain_intigrity_validity}")

        block_hash_target_validity = self.__validate_block_hash_target()
        print(f"BLOCK HASH TARGET VALIDATION  - {block_hash_target_validity}")

        validate_complete_account_balance_validity = self.__validate_complete_account_balances()
        print(f"COMPLETE ACCOUNT BALANCE VALIDATION  - {validate_complete_account_balance_validity}")

        return  chain_intigrity_validity and block_hash_target_validity and validate_complete_account_balance_validity

    def add_account(self, account):
        self._accounts[account.id] = account

    def get_account_balances(self):
        return [{'id': account.id, 'balance': account.balance} for account in self._accounts.values()]
