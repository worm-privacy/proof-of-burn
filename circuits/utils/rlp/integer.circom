pragma circom 2.2.2;

include "../../circomlib/circuits/comparators.circom";
include "../utils.circom";

// Counts the number of bytes required to store the big-endian number (i.e., ignores leading zeros).
//
// Example:
//   bytes: [0, 0, 0, 3, 0, 1, 4, 2] (3 leading-zeros)
//   len:   5
//
// Reviewers:
//   Keyvan: OK
//   Shahriar: OK
//
template CountBytes(N) {
    signal input bytes[N];
    signal output len;

    // Example:
    // bytes: [0, 0, 0, 3, 0, 1, 4, 2]

    // Checking zero-ness of each byte
    // isZero:              [1, 1, 1, 0, 1, 0, 0, 0]
    signal isZero[N];
    for (var i = 0; i < N; i++) {
        isZero[i] <== IsZero()(bytes[i]);
    }

    // Accumulating 1s until we reach a zero
    // stillZero: [*, 1, 1, 1, 0, 0, 0, 0, 0]
    // (The first element is initially set to 1)
    signal stillZero[N + 1];
    stillZero[0] <== 1;
    for (var i = 0; i < N; i++) {
        stillZero[i + 1] <== isZero[i] * stillZero[i];
    }
    
    // Number of leading-zeros = Sum of bits in stillZero
    var leadingZeros = 0;
    for (var j = 1; j < N + 1; j++) {
        leadingZeros = leadingZeros + stillZero[j];
    }

    // Number of effective bytes = N - number of leading-zeros
    len <== N - leadingZeros;
}

// Returns RLP of an integer up to 31 bytes
//
// Read: https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp/
//
// Example:
//   in: [0], out: [0x80]
//   in: [1], out: [0x01]
//   in: [10], out: [0x0a]
//   in: [127], out: [0x7f]
//   in: [128], out: [0x81,0x80]
//   in: [255], out: [0x81,0xff]
//   in: [256], out: [0x82,0x01,0x00]
//
// Reviewers:
//   Keyvan: OK
//
template RlpInteger(N) {
    signal input in;
    signal output out[N + 1];
    signal output outLen;

    // Avoid overflows.
    // Also, RLP of all numbers up to 55-bytes start with:
    //   [0x80 + num_value_bytes]
    // Instead of:
    //   [0xb7 + num_len_bytes] (Which is the case where length is above 55 bytes)
    //   (Since the amounts are never more than 31 bytes we'll never need this scenario)
    // Read: https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp/
    assert(N <= 31);

    // Calculate the big-endian version of the balance without the leading zeros
    signal bytes[N] <== Num2BigEndianBytes(N)(in);
    signal length <== CountBytes(N)(bytes);
    signal bigEndian[N] <== ShiftLeft(N)(bytes, N - length);

    // If the number is below 128, then the first byte is the number itself
    // Except when the number is zero, in that case the first byte is 0x80
    // If the number is greater than or equal 128, then the first byte is
    // (0x80 + number_of_bytes)
    signal isSingleByte <== LessThan(N * 8)([in, 128]);
    signal isZero <== IsZero()(in);
    signal firstRlpByte <== Mux1()([0x80 + length, in], isSingleByte);

    // If zero: 0 + 0x80 = 0x80 (Correct)
    // If below 128: num + 0 = num (Correct)
    // If greater than or equal 128: 0x80 + length (Correct)
    out[0] <== firstRlpByte + isZero * 0x80;
    
    // If the number is greater than or equal 128, then comes the rest of
    // the big-endian representation of bytes. Otherwise, everything is 0.
    for (var i = 1; i < N + 1; i++) {
        out[i] <== (1 - isSingleByte) * bigEndian[i - 1];
    }

    // If zero: (1 - 1) + 0 + 1 = 1 (Correct) [0x80]
    // If below 128: (1 - 1) + 1 + 0 = 1 (Correct) [num]
    // If greater than or equal 128: (1 - 0) + length + 0 = 1 + length (Correct) [0x80 + length, ...]
    outLen <== (1 - isSingleByte) + length + isZero;
}