from binascii import unhexlify
import datetime
import hashlib
from inspect import signature
from itertools import count
import json
# from logging.config import _RootLoggerConfiguration
from random import randrange
from urllib.parse import urlparse
from uuid import uuid4
import requests
from flask import Flask
from flask import jsonify, request
from ecdsa import SigningKey, VerifyingKey, NIST384p


node_address = str(uuid4()).replace('-', '')
# node_address = "abc"

class MerkleTree:
    def __init__(self,lst):
        self.n=len(lst)
        self.nlst=[0]*(4*self.n)
        self.build(0,0,len(lst)-1,lst)
    
    def merge(self,left,right):
        node_hash = hashlib.sha256((left+right).encode()).hexdigest()
        return str(node_hash)
    
    def build(self,i,l,r,lst):
        if l==r:
            self.nlst[i]=str(hashlib.sha256(str(lst[l]).encode()).hexdigest())
            return
        mid=(l+r)//2
        self.build(2*i+1,l,mid,lst)
        self.build(2*i+2,mid+1,r,lst)
        self.nlst[i]=self.merge(self.nlst[2*i+1],self.nlst[2*i+2])
        
    def root_hash(self):
        if len(self.nlst) == 0: return '00000000000'
        return self.nlst[0]

class Blockchain:
    def __init__(self) -> None:
        self.chain=[]
        self.data=[]
        self.nodes=set()
        self.mem=[]
        self.wallet=[]
        self.released_transaction = []
        self.private_key = SigningKey.generate(curve=NIST384p)
        self.public_key = self.private_key.verifying_key

    def create_block(self, previous_hash, merkle_tree_hash, proof):
        Block = {'index':len(self.chain)+1,
                 'timestamp': str(datetime.datetime.now()),
                 'data':self.data,
                 'proof': str(proof),  #also called nonce
                 'Merkle_Tree_hash':merkle_tree_hash,
                 'previous_hash':previous_hash}
        return Block
    
    def last_block(self):
        return self.chain[-1]
    
    def signn(self, transaction_hash):
        hash = hashlib.sha256(transaction_hash.encode()).hexdigest()
        return self.private_key.sign(hash.encode())
    
    def add_transaction(self,transaction):
        signature = (self.signn(str(transaction))).hex()
        
        transaction['signature'] = signature
        transaction['public_key'] = (self.public_key.to_string()).hex()
        return self.verify(transaction)
    
    def add_default_transaction(self,sender,reciever,amount):
        transaction={'sender':sender,
                     'reciever':reciever,
                     'amount':amount}
        signature = (self.signn(str(transaction))).hex()
        
        transaction['signature'] = signature
        transaction['public_key'] = (self.public_key.to_string()).hex()
        return self.verify(transaction)    
    
    def block_hash(self, block):
        encoded_block = json.dumps(block, sort_keys = True).encode()
        return hashlib.sha256(encoded_block).hexdigest()    
            
    def find_proof(self):
        previous_hash = '000000'
        if len(self.chain) != 0:
            previous_block=self.last_block()
            previous_hash = self.block_hash(previous_block)
        proof=1
        merkletree=MerkleTree(self.data)
        merkle_hash=merkletree.root_hash()
        while(True):
            block=self.create_block(previous_hash,merkle_hash,proof)
            hash=self.block_hash(block)
            if hash[:4]=="0000":
                self.chain.append(block)
                self.data=[]
                break
            proof+=1
        return proof
    
    def add_nodes(self,address):
        parsed_url = urlparse(address)
        self.nodes.add(parsed_url.netloc)
    
    def is_chain_valid(self, chain):
        previous_block = chain[0]
        block_index = 1
        while block_index < len(chain):
            block = chain[block_index]
            if block['previous_hash'] != self.block_hash(previous_block):
                return False
            if block['previous_hash'][:4] != '0000':
                return False
            previous_block = block
            block_index += 1
        return True
    
    def replace_chain(self):
        longest_chain=[]
        max_length = 0
        for node in self.nodes:
            response = requests.get(f'http://{node}/get_chain')
            if response.status_code==200:
                length = response.json()['length']
                chain = response.json()['chain']
                if length > max_length and self.is_chain_valid(chain):
                    max_length = length
                    longest_chain = chain
        if len(longest_chain) != 0:
            self.chain = longest_chain
            self.replace_mempool()
            self.wallet_money()
            return True
        return False       
    
    def Mempool(self, transaction):
        nodes=self.nodes
        for node in nodes:
            response = requests.get(f'http://{node}/get_mempool')
            if response.status_code == 200:
                MemPool=response.json()['mempool']
                MemPool.append(transaction)
                requests.post(f'http://{node}/update_mempool', data={'mempool': MemPool})
                
    
    def replace_mempool(self):
        for transaction in self.chain[-1]['data']:
            if transaction in self.mem: 
                self.mem.remove(transaction)
    
    def verify(self, transaction):
        is_added = False
        for node in self.nodes:
            response = requests.get(f'http://{node}/get_address')
            address = response.json()['address']
            if response.status_code == 200:
                if transaction['reciever'] == address and self.check(transaction):
                    if len(self.released_transaction) != 0:
                        self.free()
                        self.released_transaction=[]
                    # print(transaction)
                    self.mem.append(transaction)
                    # self.Mempool(transaction)
                    is_added = True
        if is_added:
            return True
        else:
            return False
            
    def mine_block(self):
        if len(self.mem) != 0:
            count_transaction=0
            for transaction in self.mem:
                if count_transaction == 1: # or transaction == self.mem[-1]:
                    break
                else :
                    self.data.append(transaction)
                    count_transaction += 1   
            self.find_proof()

    def wallet_money(self):
        block=self.chain[-1]
        for transaction in block['data']:
            copy_transaction = transaction.copy()
            if transaction['reciever'] == node_address:
                del(copy_transaction['signature'])
                del(copy_transaction['public_key'])
                self.wallet.append(copy_transaction)
    
    def check(self,transaction):
        copy_transaction=transaction.copy()
        signature=unhexlify(copy_transaction['signature'])
        del(copy_transaction['signature'])
        public_key=unhexlify(copy_transaction['public_key'])
        public_key_r=VerifyingKey.from_string(public_key, curve=NIST384p)
        del(copy_transaction['public_key'])
        hash_check = hashlib.sha256((str(copy_transaction)).encode()).hexdigest()
        return public_key_r.verify(signature,hash_check.encode())
    
    def wallet_operation(self,amount_to_pay,released_transaction,receiver_address):
        total_money=0
        for transaction in released_transaction:
            if transaction in self.wallet:
                total_money += transaction['amount']    
            else:
                return False
        
        if amount_to_pay > total_money:
            return False
        
        for transaction in released_transaction:
            self.released_transaction.append(transaction)
        
        new_transaction = {'sender': node_address,
                           'reciever': receiver_address,
                           'amount': amount_to_pay}
        
        if total_money > amount_to_pay:
            transaction_to_itself = {'sender': node_address,
                                 'reciever': node_address,
                                 'amount': total_money - amount_to_pay}
            self.add_transaction(transaction_to_itself)
        
        self.add_transaction(new_transaction)
        
        return True
    
    def free(self):
        for transaction in self.released_transaction:
            self.wallet.remove(transaction)
        
         
        
app = Flask(__name__)


# data=["a1","a2","a3"]
blockchain=Blockchain()
# merkel=MerkleTree(data)
# print(merkel.root_hash())

@app.route('/get_chain', methods = ['GET'])
def get_chain():
    response = {'chain': blockchain.chain,
                'length': len(blockchain.chain)}
    return jsonify(response), 200

@app.route('/get_mempool', methods = ['GET'])
def get_mempool():
    response = {'mempool': blockchain.mem}
    return jsonify(response), 200


@app.route('/update_mempool', methods = ['POST'])
def update_mempool():
    json = request.get_json()
    # response = {'mempool': json['mempool']}
    # blockchain.mem = json['mempool']
    # print(blockchain.mem)
    # return 200


@app.route('/get_address', methods = ['GET'])
def get_address():
    response = {'address': node_address}
    return jsonify(response), 200

@app.route('/get_wallet', methods = ['GET'])
def get_wallet():
    response = {'wallet': blockchain.wallet}
    return jsonify(response), 200

@app.route('/is_valid', methods = ['GET'])
def is_valid():
    is_valid = blockchain.is_chain_valid(blockchain.chain)
    if is_valid:
        response = {'message': 'All good. The Blockchain is valid.'}
    else:
        response = {'message': 'Guys, we have a problem. The Blockchain is not valid.'}
    return jsonify(response), 200


@app.route('/add_transaction', methods = ['POST'])
def add_transaction():
    json = request.get_json()
    transaction_keys = ['receiver','amount','released_transactions']
    if not all(key in json for key in transaction_keys):
        return 'Some elements of the transaction are missing', 400
    is_added = blockchain.wallet_operation(json['amount'], json['released_transactions'], json['receiver'])
    response = {'message': f'This transaction is verified and is added to the MemPool'}
    if is_added:
        return jsonify(response), 201
    else:
        return 'Please Enter Right reciever Address or Released Transaction Money is not enough', 400

@app.route('/connect_node', methods = ['POST'])
def connect_node():
    json = request.get_json()
    nodes = json.get('nodes')
    if nodes is None:
        return "No node", 400
    for node in nodes:
        blockchain.add_nodes(node)
    response = {'message': 'All the nodes are now connected. The Hadcoin Blockchain now contains the following nodes:',
                'total_nodes': list(blockchain.nodes)}
    return jsonify(response), 201


@app.route('/replace_chain', methods = ['GET'])
def replace_chain():
    is_chain_replaced = blockchain.replace_chain()
    if is_chain_replaced:
        response = {'message': 'The nodes had different chains so the chain was replaced by the longest one.',
                    'new_chain': blockchain.chain}
    else:
        response = {'message': 'All good. The chain is the largest one.',
                    'actual_chain': blockchain.chain}
    return jsonify(response), 200 


@app.route('/mine_block', methods = ['GET'])
def mine_block():
    blockchain.mine_block()
    response = 'Block is mined'
    return jsonify(response), 200


@app.route('/add_default_transaction', methods = ['POST'])
def add_default_transaction():
    json = request.get_json()
    transaction_keys = ['sender', 'receiver', 'amount']
    if not all(key in json for key in transaction_keys):
        return 'Some elements of the transaction are missing', 400
    index = blockchain.add_default_transaction(json['sender'], json['receiver'], json['amount'])
    response = {'message': f'This transaction will be added to Block {index}'}
    return jsonify(response), 201


print(node_address)

app.run(host = '0.0.0.0', port = 5001)


