
pragma circom 2.2.2;

include "./assert.circom";

// Fits a M-element array in a N-element block
//
// Reviewers:
//   Keyvan: OK
//
template Fit(M, N) {
    signal input in[M];
    signal output out[N];
    for(var i = 0; i < N; i++) {
        if(i < M) {
            out[i] <== in[i];
        } else {
            out[i] <== 0;
        }
    }
}

// Flattens a 2D array into a 1D array
//
// Reviewers:
//   Keyvan: OK
//
template Flatten(M, N) {
    signal input in[M][N];
    signal output out[M * N];
    for(var i = 0; i < M; i++) {
        for(var j = 0; j < N; j++) {
            out[i * N + j] <== in[i][j];
        }
    }
}

// Reshapes a 1D array into a 2D array
//
// Reviewers:
//   Keyvan: OK
//
template Reshape(M, N) {
    signal input in[M * N];
    signal output out[M][N];
    for(var i = 0; i < M; i++) {
        for(var j = 0; j < N; j++) {
            out[i][j] <== in[i * N + j];
        }
    }
}

// Computes the quotient and remainder for the division of a by b:
// a === out * b + rem
//
// Example:
//   a:   10
//   b:   3
//   out: 3
//   rem: 1
//
// Reviewers:
//   Keyvan: OK
//
template Divide(N) {
    signal input a;
    signal input b;
    signal output out;
    signal output rem;

    out <-- a \ b;
    rem <-- a % b;

    // Check if `rem` and `b` are at most N-bits long and `rem < b`
    AssertLessThan(N)(rem, b);

    // Check if `out` and `a` are at most N-bits long and `out < a`
    AssertLessEqThan(N)(out, a);

    out * b + rem === a;
}

// Reverses the input array
//
// Reviewers:
//   Keyvan: OK
//
template Reverse(N) {
    signal input in[N];
    signal output out[N];
    for(var i = 0; i < N; i++) {
        out[i] <== in[N - 1 - i];
    }
}

// Converts little-endian bytes to num
//
// Reviewers:
//   Keyvan: OK
//
template Bytes2Num(N) {
    signal input in[N];
    signal output out;

    assert(N <= 31); // Avoid overflows

    var lc = 0;
    for(var i = 0; i < N; i++) {
        lc += (256 ** i) * in[i];
    }

    out <== lc;
}

// Converts big-endian bytes to num
//
// Reviewers:
//   Keyvan: OK
//
template Bytes2NumBigEndian(N) {
    signal input in[N];
    signal output out;

    signal inReversed[N] <== Reverse(N)(in);
    out <== Bytes2Num(N)(inReversed);
}

// Decomposes an input number `num` into an array of `N` bytes.
// Each byte represents 8 bits of the number starting from the least significant byte.
//
// Example:
//   num:   66051
//   N:     8
//   bytes: [3, 2, 1, 0, 0, 0, 0, 0]
//
// Reviewers:
//   Keyvan: OK
//
template Num2Bytes(N) { 
    signal input num;
    signal output bytes[N];

    assert(N <= 31); // Avoid overflows

    // Decompose into bits and arrange them into 8-bit chunks
    signal bits[N * 8] <== Num2Bits(N * 8)(num);
    signal byteBits[N][8];
    for (var i = 0; i < N; i++) {
        for(var j = 0; j < 8; j++) {
            byteBits[i][j] <== bits[8 * i + j];
        }
    }

    // Convert 8-bit chunks to bytes
    for (var i = 0; i < N; i++) {
        bytes[i] <== Bits2Num(8)(byteBits[i]);
    }
}

// Convert a field element to 256-bits
//
// Reviewers:
//   Keyvan: OK
//
template Num2BytesBigEndian() {
    signal input in;
    signal output out[32];

    signal bitsStrict[254] <== Num2Bits_strict()(in);
    signal bits[256] <== Fit(254, 256)(bitsStrict); // Set the 2 remaining bytes to zero
    signal byteArrays[32][8] <== Reshape(32, 8)(bits);
    signal bytes[32];
    for(var i = 0; i < 32; i++) {
        bytes[i] <== Bits2Num(8)(byteArrays[i]);
    }
    out <== Reverse(32)(bytes);
}

// Accepts N bytes and outputs 2xN nibbles (As a list of 4-bit numbers)
//
// Reviewers:
//   Keyvan: OK
//
template Bytes2Nibbles(N) {
    signal input in[N];
    signal output out[2 * N]; // Each byte is 2 nibbles

    signal inDecomposed[N][8];

    for(var i = 0; i < N; i++) {
        inDecomposed[i] <== Num2Bits(8)(in[i]);
        var higher = 0;
        var lower = 0;
        for(var j = 0; j < 4; j++) {
            lower += inDecomposed[i][j] * (2 ** j);
            higher += inDecomposed[i][j + 4] * (2 ** j);
        }
        out[2 * i] <== higher;
        out[2 * i + 1] <== lower;
    }
}

// Converts an array of nibbles (4-bit values) into an array of bytes (8-bit values).
// Each byte is formed by combining two nibbles (4 bits each).
//
// Example:
//   nibbles: [0x1, 0x2, 0x3, 0x4, 0x5, 0x6]
//   bytes: [0x12, 0x34, 0x56]
//
// Reviewers:
//   Keyvan: OK
//
template Nibbles2Bytes(n) {
    signal input nibbles[2 * n];
    signal output bytes[n];
    for(var i = 0; i < n; i++) {
        // Check if all nibbles are maximum 4-bit long
        AssertBits(4)(nibbles[2 * i]);
        AssertBits(4)(nibbles[2 * i + 1]);

        bytes[i] <== nibbles[2 * i] * 16 + nibbles[2 * i + 1];
    }
}