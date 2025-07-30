import json
import web3
import rlp
from hexbytes.main import HexBytes
from poseidon2 import poseidon2, poseidon3, Field, FIELD_SIZE

MAX_HEADER_BYTES = 5 * 136
MAX_LAYER_BYTES = 4 * 136
MAX_NUM_LAYERS = 4
POW_MIN_ZERO_BYTES = 2


w3 = web3.Web3(provider=web3.Web3.HTTPProvider("http://127.0.0.1:8545"))


def burn(burn_key, receiver, fee):
    recv = web3.Web3.to_int(hexstr=receiver)
    account_1 = "0x90F8bf6A479f320ead074411a4B0e7944Ea8c9C1"
    private_key = "0x4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d"
    nonce = w3.eth.get_transaction_count(account_1)
    hashed = w3.to_bytes(poseidon3(Field(burn_key), Field(recv), Field(fee)).val)
    addr = list(hashed[:20])
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


def find_burn_key(receiver_address, fee, min_zero_bytes):
    receiver_address_bytes = int.to_bytes(receiver_address, 20, "big")
    fee_bytes = int.to_bytes(fee, 32, "big")
    burn_key = random.randint(0, FIELD_SIZE - 1)
    while any(
        w3.keccak(
            int.to_bytes(burn_key, 32, "big")
            + receiver_address_bytes
            + fee_bytes
            + b"EIP-7503"
        )[:min_zero_bytes]
    ):
        burn_key += 1
    return burn_key


fee = 123
spend = 234
receiver = "0x90F8bf6A479f320ead074411a4B0e7944Ea8c9C1"
burn_key = find_burn_key(int(receiver[2:], 16), fee, POW_MIN_ZERO_BYTES)
addr = burn(burn_key, receiver, fee)

blknum = w3.eth.block_number
proof = w3.eth.get_proof(addr, [], blknum)
block = w3.eth.get_block(blknum)

addr_hash = w3.keccak(hexstr=addr)
leaf = proof.accountProof[-1]
(term, account_rlp) = tuple(rlp.decode(leaf))
if term[0] & 0xF0 == 0x20:
    addr_term_len = 2 * len(term) - 2
elif term[0] & 0xF0 == 0x30:
    addr_term_len = 2 * len(term) - 1
else:
    raise Exception("Invalid")
# print(term.hex(), addr_term_len)
# exit(0)
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


# def bytes_to_bits(bytes):
#     out = []
#     for byte in bytes:
#         lst = [int(a) for a in list(reversed(bin(byte)[2:]))]
#         for i in range(8):
#             out.append(lst[i] if i < len(lst) else 0)
#     return out


header_bytes = list(header)
header_bytes_len = len(header_bytes)
header_bytes = header_bytes + [0] * (MAX_HEADER_BYTES - header_bytes_len)

layers = []
layer_lens = []
for layer_bytes in list(proof.accountProof):
    layer = list(layer_bytes)
    layer_len = len(layer)
    layer += [0] * (MAX_LAYER_BYTES - layer_len)
    layers.append(layer)
    layer_lens.append(layer_len)

num_layers = len(layers)
while len(layers) < MAX_NUM_LAYERS:
    layers.append([0] * MAX_LAYER_BYTES)
    layer_lens.append(256)
import io

with io.open("details.json", "w") as f:
    json.dump(
        [
            block.hash.hex(),
        ],
        f,
    )
print(
    json.dumps(
        {
            "receiverAddress": str(web3.Web3.to_int(hexstr=receiver)),
            "numLeafAddressNibbles": str(addr_term_len),
            "burnKey": str(burn_key),
            "fee": str(fee),
            "balance": str(proof.balance),
            "spend": str(spend),
            "numLayers": num_layers,
            "layers": layers,
            "layerLens": layer_lens,
            "blockHeader": header_bytes,
            "blockHeaderLen": header_bytes_len,
            "byteSecurityRelax": 0,
        },
    )
)
