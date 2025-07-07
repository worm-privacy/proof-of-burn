pragma circom 2.2.2;

include "../circomlib/circuits/poseidon.circom";

// Poseidon is a lightweight cryptographic hash function designed for zk-SNARKs
//
// Reviewers:
//   Keyvan: OK
//
template Hasher() {
    signal input left;
    signal input right;
    signal output hash;

    hash <== Poseidon(2)([left, right]);
}