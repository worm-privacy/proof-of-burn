# a=[1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0]
import json
import web3
import rlp
from hexbytes.main import HexBytes

MAX_HEADER_BITS = 5 * 136 * 8
MAX_NUM_LAYERS = 12

w3 = web3.Web3(provider=web3.Web3.HTTPProvider("https://rpc.payload.de/"))
addr = "0x000000000000000000000000000000000000dEaD"
blknum = w3.eth.block_number
proof = w3.eth.get_proof(addr, [], blknum)
block = w3.eth.get_block(blknum)

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
    layer_lens.append(0)
print(
    json.dumps(
        {
            "balance": str(proof.balance),
            "numLayers": num_layers,
            "layerBits": layers,
            "layerBitsLens": layer_lens,
            "blockRoot": block_root,
            "nullifier": [0] * 31 * 8 + [0, 1, 0, 1, 0, 1, 1, 1],
            "encryptedBalance": [0] * 30 * 8
            + [1, 0, 0, 0, 0, 0, 0, 0]
            + [1, 0, 0, 1, 1, 0, 1, 0],
            "blockHeader": header_bits,
            "blockHeaderLen": header_bits_len,
        },
    )
)

#'0xd5e9b28c27b288e692ca3bc64dfd3bb8dcace6705f1f4f344b9fbd9dfae5247f'
