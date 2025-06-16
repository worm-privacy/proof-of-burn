import json
import web3
import rlp
from hexbytes.main import HexBytes
from mimc7 import mimc7, Field, FIELD_SIZE

MAX_HEADER_BITS = 5 * 136 * 8
MAX_NUM_LAYERS = 4
POW_BITS = 250


w3 = web3.Web3(provider=web3.Web3.HTTPProvider("http://127.0.0.1:8545"))


def burn(entropy):
    account_1 = "0x90F8bf6A479f320ead074411a4B0e7944Ea8c9C1"
    private_key = "0x4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d"
    nonce = w3.eth.get_transaction_count(account_1)
    hashed = w3.to_bytes(mimc7(Field(entropy), Field(0)).val)
    addr = list(hashed[len(hashed)-20:])
    burn_addr = w3.to_checksum_address(bytes(addr))
    tx = {
        "nonce": nonce,
        "to": burn_addr,
        "value": w3.to_wei(1, "ether"),
        "gas": 2000000,
        "gasPrice": w3.to_wei(50, "gwei"),
    }
    signed_tx = w3.eth.account.sign_transaction(tx, private_key)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
    assert w3.eth.wait_for_transaction_receipt(tx_hash).status == 1
    return burn_addr

import random
def find_entropy(max_bits):
    entropy = random.randint(0, FIELD_SIZE - 1)
    while len(bin(mimc7(Field(entropy), Field(2)).val)[2:]) > max_bits:
        entropy += 1
    return entropy

entropy = find_entropy(POW_BITS)
addr = burn(entropy)

blknum = w3.eth.block_number
proof = w3.eth.get_proof(addr, [], blknum)
block = w3.eth.get_block(blknum)


addr_hash = w3.keccak(hexstr=addr)
leaf = proof.accountProof[-1]
(term, account_rlp) = tuple(rlp.decode(leaf))
if term[0] & 0xf0 == 0x20:
    addr_term_len = 2*len(term) - 2
elif term[0] & 0xf0 == 0x30:
    addr_term_len = 2*len(term) - 1
else:
    raise Exception("Invalid")
#print(term.hex(), addr_term_len)
#exit(0)
MAX_TERM_LEN = 64
term_len = len(term)
term = list(term) + [0] * (MAX_TERM_LEN - term_len)

hashes = [
    block.parentHash.hex(),
    block.sha3Uncles.hex(),
    block.miner,
    block.stateRoot.hex(),
    block.transactionsRoot.hex(),
    block.receiptsRoot.hex(),
    block.logsBloom.hex(),
    hex(block.difficulty),
    hex(block.number),
    hex(block.gasLimit),
    hex(block.gasUsed),
    hex(block.timestamp),
    block.extraData.hex(),
    block.mixHash.hex(),
    block.nonce.hex(),
]

optional_headers = [
    "baseFeePerGas",
    "withdrawalsRoot",
    "blobGasUsed",
    "excessBlobGas",
    "parentBeaconBlockRoot",
    "requestsHash",
]

for header in optional_headers:
    if hasattr(block, header):
        v = getattr(block, header)
        if isinstance(v, HexBytes):
            hashes.append(v.hex())
        elif isinstance(v, int):
            hashes.append(hex(v))
        else:
            hashes.append(v)

hashes = ["0x" if h == "0x0" else h for h in hashes]
header = rlp.encode([w3.to_bytes(hexstr=h) for h in hashes])


def bytes_to_bits(bytes):
    out = []
    for byte in bytes:
        lst = [int(a) for a in list(reversed(bin(byte)[2:]))]
        for i in range(8):
            out.append(lst[i] if i < len(lst) else 0)
    return out


header_bits = bytes_to_bits(header)
header_bits_len = len(header_bits)
header_bits = header_bits + [0] * (MAX_HEADER_BITS - header_bits_len)
block_root = bytes_to_bits(block.hash)

layers = []
layer_lens = []
for layer_bytes in list(proof.accountProof):
    layer = bytes_to_bits(list(layer_bytes))
    layer_len = len(layer)
    layer += [0] * (4 * 136 * 8 - layer_len)
    layers.append(layer)
    layer_lens.append(layer_len)

num_layers = len(layers)
while len(layers) < MAX_NUM_LAYERS:
    layers.append([0] * (4 * 136 * 8))
    layer_lens.append(256)
import io
with io.open("details.json", 'w') as f:
    json.dump({
        "addr": addr,
        "addrHash": w3.keccak(hexstr=addr).hex()
    }, f)

fee = 123
print(
    json.dumps(
        {
            "numLeafAddressNibbles": str(addr_term_len),
            "entropy": str(entropy),
            "fee": str(fee),
            "balance": str(proof.balance),
            "numLayers": num_layers,
            "layerBits": layers,
            "layerBitsLens": layer_lens,
            "blockHeader": header_bits,
            "blockHeaderLen": header_bits_len,
        },
    )
)