pragma circom 2.2.2;

include "../circomlib/circuits/mimcsponge.circom";

// MiMC is a lightweight cryptographic hash function designed for zk-SNARKs
// TornadoCash also uses this for its merkle-tree implementation
//
// Reviewers:
//   Keyvan: OK
//
template Hasher() {
    signal input left;
    signal input right;
    signal output hash;

    component hasher = MiMCSponge(2, 220, 1);
    hasher.ins[0] <== left;
    hasher.ins[1] <== right;
    hasher.k <== 0;
    hash <== hasher.outs[0];
}