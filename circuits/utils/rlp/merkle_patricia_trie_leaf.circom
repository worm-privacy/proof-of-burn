pragma circom 2.2.2;

include "../../circomlib/circuits/comparators.circom";
include "../../circomlib/circuits/mux1.circom";
include "../convert.circom";
include "../shift.circom";
include "../concat.circom";
include "./empty_account.circom";

// Takes `2 * addressHashBytes` nibbles and keeps `addressHashNibblesLen` of them with this pattern:
//
//   1. If even number of nibbles: [0x20, rest_of_the_nibbles_as_bytes]
//   2. If odd number of nibbles:  [0x30 + first_nibble, rest_of_the_nibbles_as_bytes]
//
// (Read more: https://ethereum.org/en/developers/docs/data-structures-and-encoding/patricia-merkle-trie/#specification)
//
// Example:
//   in:     [0x1, 0x2, 0x3, 0x4]
//   len:    4
//   out:    [0x20, 0x12, 0x34]
//   outLen: 3
//
// Example:
//   in:     [0x1, 0x2, 0x3, 0x4]
//   len:    3
//   out:    [0x32, 0x34, 0x00]
//   outLen: 2
//
// Example:
//   in:     [0x1, 0x2, 0x3, 0x4]
//   len:    2
//   out:    [0x20, 0x34, 0x00]
//   outLen: 2
//
// Example:
//   in:     [0x1, 0x2, 0x3, 0x4]
//   len:    1
//   out:    [0x34, 0x00, 0x00]
//   outLen: 1
//
// Example:
//   in:     [0x1, 0x2, 0x3, 0x4]
//   len:    0
//   out:    [0x20, 0x00, 0x00]
//   outLen: 1
//
// Reviewers:
//   Keyvan: OK
//
template TruncatedAddressHash(addressHashBytes) {
    signal input addressHashNibbles[2 * addressHashBytes];
    signal input addressHashNibblesLen;
    signal output out[addressHashBytes + 1];
    signal output outLen;

    // addressHash is at most 32 bytes (64 nibbles) so 7 bits
    AssertLessEqThan(7)(addressHashNibblesLen, 2 * addressHashBytes);

    // Check odd/evenness
    signal (div, rem) <== Divide(7)(addressHashNibblesLen, 2);

    // Shift left (2 * addressHashBytes - addressHashNibblesLen) times so that
    // the last addressHashNibblesLen nibbles remain
    signal shifted[2 * addressHashBytes] <== ShiftLeft(2 * addressHashBytes)(
        addressHashNibbles, 2 * addressHashBytes - addressHashNibblesLen);

    signal outNibbles[2 * addressHashBytes + 2];
    // 2 if even number of nibbles, 3 if odd number of nibbles
    outNibbles[0] <== 2 + rem;

    // If odd number of nibbles, the second nibble of the result 
    // should be the first nibble of the remaining value
    // If even number of nibbles, the second nibble is 0
    outNibbles[1] <== rem * shifted[0]; 

    signal temp[2 * addressHashBytes - 1];

    // If odd number of nibbles, shift-right by one
    for(var i = 0; i < 2 * addressHashBytes; i++) {
        if(i < 2 * addressHashBytes - 1) {
            outNibbles[i + 2] <== Mux1()([shifted[i], shifted[i + 1]], rem);
        } else {
            // Avoid index out of bound
            outNibbles[i + 2] <== (1 - rem) * shifted[i];
        }
    }

    out <== Nibbles2Bytes(addressHashBytes + 1)(outNibbles);
    outLen <== 1 + div;
}

// Returns RLP(key, value)
// Where:
//   key:   addressHash (Truncated to addressHashNibblesLen nibbles with certain encoding)
//   value: RLP([NONCE, balance, STORAGE_HASH, CODE_HASH])
//
// Read: https://ethereum.org/en/developers/docs/data-structures-and-encoding/patricia-merkle-trie/
//
// Reviewers:
//   Keyvan: OK
//
template RlpMerklePatriciaTrieLeaf(maxAddressHashBytes, maxBalanceBytes) {
    signal input addressHashNibbles[2 * maxAddressHashBytes];
    signal input addressHashNibblesLen;
    signal input balance;

    assert(maxAddressHashBytes <= 32);
    assert(maxBalanceBytes <= 31);

    // Min length: 4 + 0 + 66 = 70
    // Max length: 4 + 31 + 66 = 101
    // The "value" in a leaf node is RLP of an account
    var maxRlpEmptyAccountLen = 4 + maxBalanceBytes + 66; // More info in RlpEmptyAccount gadget
    assert(maxRlpEmptyAccountLen <= 101);

    // Min length: 2 + 70 = 72
    // Max length: 2 + 101 = 103
    // Byte-strings of length more than 55 bytes and less than 256 bytes are prefixed with:
    // [0xb7 + 1, STRING_LEN]
    var maxValueRlpLen = 2 + maxRlpEmptyAccountLen; // Prefix: [0xb7 + 1, VALUE_LEN]
    assert(maxValueRlpLen <= 103);

    // Leaf keys are prefixed with 0x20 or 0x3_
    // Read: https://ethereum.org/de/developers/docs/data-structures-and-encoding/patricia-merkle-trie/#specification
    // Min length: 2 (We later put an AssertGreaterEqThan on the keyLen to avoid keyLens lower than 2)
    // Max length: 33
    var maxKeyLen = 1 + maxAddressHashBytes; 
    assert(maxKeyLen <= 33);

    // keyLen is at least 2 bytes and at most 33 bytes, so [0x80 + keyLen] is the correct prefix
    // Min length: 3
    // Max length: 34
    var maxKeyRlpLen = 1 + maxKeyLen; // Prefix: [0x80 + KEY_LEN]
    assert(maxKeyRlpLen <= 34);

    // KEY_RLP_LEN + VALUE_RLP_LEN is minimum (3 + 73 = 76) and maximum (34 + 103 = 137) bytes
    // So the correct prefix is always: [0xf7 + 1, KEY_RLP_LEN + VALUE_RLP_LEN]
    var maxPrefixedKeyRlpLen = 2 + maxKeyRlpLen;
    assert(maxKeyRlpLen + maxValueRlpLen <= 137);

    // maxBalanceBytes + maxAddressHashBytes + 76
    var maxOutLen = maxPrefixedKeyRlpLen + maxValueRlpLen; 

    signal output out[maxOutLen];
    signal output outLen;

    // Calculate the MPT leaf key based on the address-hash nibbles
    signal (key[maxKeyLen], keyLen) <== TruncatedAddressHash(32)(addressHashNibbles, addressHashNibblesLen);    

    // A minimum of 2 bytes so that the prefix of key is always [0x80 + len]
    AssertGreaterEqThan(16)(keyLen, 2);

    signal (
        rlpEmptyAccount[maxRlpEmptyAccountLen], rlpEmptyAccountLen
    ) <== RlpEmptyAccount(maxBalanceBytes)(balance);
    
    // Key is the RLP-encoding of part of the address-hash.
    // (NOTE: This is also prefixed with the RLP of the whole leaf)
    signal prefixedKeyRlp[maxPrefixedKeyRlpLen];
    signal prefixedKeyRlpLen;

    // Value is the RLP-encoding of an empty-account RLP.
    signal valueRlp[maxValueRlpLen];
    signal valueRlpLen;

    valueRlp[0] <== 0xb7 + 1;
    valueRlp[1] <== rlpEmptyAccountLen;
    for(var i = 0; i < maxRlpEmptyAccountLen; i++) {
        valueRlp[i + 2] <== rlpEmptyAccount[i];
    }
    valueRlpLen <== 2 + rlpEmptyAccountLen;

    // Prefix of the whole leaf: RLP([key, value])
    prefixedKeyRlp[0] <== 0xf7 + 1;
    prefixedKeyRlp[1] <== (keyLen + 1) + valueRlpLen; // (keyLen + 1) is keyRlpLen

    prefixedKeyRlp[2] <== 0x80 + keyLen;
    for(var i = 0; i < 33; i++) {
        prefixedKeyRlp[i + 3] <== key[i];
    }
    prefixedKeyRlpLen <== 3 + keyLen;

    (out, outLen) <== Concat(maxPrefixedKeyRlpLen, maxValueRlpLen)(
        a <== prefixedKeyRlp,
        aLen <== prefixedKeyRlpLen,
        b <== valueRlp,
        bLen <== valueRlpLen
    );
}

// Checks if lower <= value <= upper
//
// Reviewers:
//   Keyvan: OK
//
template IsInRange(B) {
    signal input lower;
    signal input value;
    signal input upper;
    signal output out;
    AssertBits(B)(lower);
    AssertBits(B)(value);
    AssertBits(B)(upper);
    signal lowerLteValue <== LessEqThan(B)([lower, value]); // lower <= value
    signal valueLteUpper <== LessEqThan(B)([value, upper]); // value <= upper
    out <== lowerLteValue * valueLteUpper; // lowerLteValue && valueLteUpper (lower <= value <= upper)
}

// Checks if the input layer looks like a MPT leaf
//
// Reviewers:
//   Keyvan: OK
//
template LeafDetector(N) {
    signal input layer[N];
    signal input layerLen;
    signal output isLeaf;

    // Leaves all start with 0xf8 because of their min/max size
    signal leafPrefixIsF8 <== IsEqual()([layer[0], 0xf8]);
    signal totalLength <== layer[1];
    signal isConsistentWithLayerLen <== IsEqual()([totalLength + 2, layerLen]); // 2 prefix bytes
    signal keyLenEncoded <== layer[2];

    // Make sure 0x81 <= keyLenEncoded <= 0xb7
    signal keyLenIsInRange <== IsInRange(16)(0x81, keyLenEncoded, 0xb7);

    // Make keyLen zero in case keyLen is not in range in order to prevent Selector 
    // components from panicking because of out-of-range assertions.
    signal keyLen <== keyLenIsInRange * (keyLenEncoded - 0x80);

    // Value comes right after the key
    // Value is wrapped in an outer RLP [0xf7 + 1, valueLen + 2, 0xf7 + 1, valueLen] + value
    signal valueWrapperPrefix <== Selector(N)(layer, 3 + keyLen + 0);
    signal valueWrapperPrefixIsB8 <== IsEqual()([valueWrapperPrefix, 0xb8]);
    signal valueWrapperLen <== Selector(N)(layer, 3 + keyLen + 1);

    signal valueLenEncoded <== Selector(N)(layer, 3 + keyLen + 2);
    signal valueLenEncodedIsF8 <== IsEqual()([valueLenEncoded, 0xf8]);
    signal valueLen <== Selector(N)(layer, 3 + keyLen + 2 + 1);
    signal isValueWrapperLenConsistent <== IsEqual()([valueWrapperLen, valueLen + 2]);
    signal isKeyValueLenEqualWithLayerLen <== IsEqual()([keyLen + valueLen + 7, layerLen]);

    isLeaf <== MultiAND(7)([
        leafPrefixIsF8, isConsistentWithLayerLen, keyLenIsInRange, 
        valueWrapperPrefixIsB8, isValueWrapperLenConsistent, 
        valueLenEncodedIsF8, isKeyValueLenEqualWithLayerLen
    ]);
}