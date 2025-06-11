pragma circom 2.1.5;

include "./utils.circom";

// Shifts the `in` array to the left by the given `count` times, filling the end with zeros.
//
// Example:
//   in: [1, 2, 3, 4, 5]
//   count: 2
//   out: [3, 4, 5, 0, 0]
template ShiftLeft(n) {
    signal input in[n];
    signal input count;
    signal output out[n];

    signal outsum[n][n+1];
    for(var i = 0; i < n; i++) {
        outsum[i][0] <== 0;
    }
    component eqs[n][n];
    for(var i = 0; i < n; i++) {
        for(var j = 0; j < n; j++) {
            eqs[i][j] = IsEqual();
            eqs[i][j].in[0] <== i;
            eqs[i][j].in[1] <== j - count;
            outsum[i][j+1] <== outsum[i][j] + eqs[i][j].out * in[j];
        }
        out[i] <== outsum[i][n];
    }
}

template LeafKey(N) {
    signal input address[N];
    signal input count;
    signal output out[N+2];
    signal output outLen;

    component div = Divide(16);
    div.a <== count;
    div.b <== 2;

    component shifted = ShiftLeft(N);
    shifted.in <== address;
    shifted.count <== count;
    signal temp[N - 1];
    for(var i = 0; i < N; i++) {
        if(i == N - 1) {
            out[i+2] <== (1 - div.rem) * shifted.out[i];
        } else {
            temp[i] <== div.rem * shifted.out[i+1];
            out[i+2] <== (1 - div.rem) * shifted.out[i] + temp[i];
        }
    }
    out[0] <== 2 + div.rem;
    out[1] <== div.rem * shifted.out[0];
    outLen <== N + 2 - count - div.rem;
}