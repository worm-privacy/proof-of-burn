import web3

MAX_LEN = 512
MAX_LAYERS = 10

layers = [[1, 2, 3], [4, 5, 6]]
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
layers = [{', '.join([layer_to_str(l) for l in layers])}]
layerSizes = [{', '.join(['"' + str(sz) + '"' for sz in layer_sizes])}]
"""

print(out)
