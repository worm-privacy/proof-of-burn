import web3

MAX_LEN = 768
MAX_LAYERS = 10

w3 = web3.Web3(provider=web3.Web3.HTTPProvider("https://rpc.payload.de/"))
addr = "0x000000000000000000000000000000000000dEaD"

blknum = w3.eth.block_number
proof = w3.eth.get_proof(addr, [], blknum)
state_root = w3.eth.get_block(blknum).stateRoot
addr_hash = web3.Web3.keccak(hexstr=addr)[10:]
leaf = proof.accountProof[-1]
prefix = leaf[: leaf.index(addr_hash) + 22]

extracted_layers = []
for layer in list(reversed(proof.accountProof))[1:]:
    extracted_layers.append(list(layer))

balance = proof.balance

leaf_prefix = list(prefix)
leaf_prefex_size = len(leaf_prefix)
leaf_prefix = leaf_prefix + [0] * (MAX_LEN - leaf_prefex_size)

layers = extracted_layers
num_layers = len(layers)
layer_sizes = [len(l) for l in layers]

for i in range(len(layers)):
    padded_layer = layers[i] + [0] * (MAX_LEN - len(layers[i]))
    layers[i] = padded_layer

layer_sizes += [0] * (MAX_LAYERS - len(layers))
layers += [[0] * MAX_LEN] * (MAX_LAYERS - len(layers))


def layer_to_str(layer):
    inner = ", ".join(['"' + str(p) + '"' for p in layer])
    return f"[{inner}]"


out = f"""
leaf_prefix = {layer_to_str(leaf_prefix)}
leaf_prefix_size = "{leaf_prefex_size}"
balance = "{balance}"
address = {layer_to_str(web3.Web3.to_bytes(hexstr=addr))}
layers = [{', '.join([layer_to_str(l) for l in layers])}]
layer_sizes = [{', '.join(['"' + str(sz) + '"' for sz in layer_sizes])}]
num_layers = "{num_layers}"
secret = "0"
"""

print(out)
