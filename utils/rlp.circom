pragma circom 2.1.5;

include "../circomlib/circuits/comparators.circom";
include "../circomlib/circuits/mux1.circom";
include "./utils.circom";
include "./concat.circom";


template GetRealByteLength(N) {
    signal input bytes[N];
    signal output len;

    component isZero[N];

    signal isZeroResult[N+1];
    isZeroResult[0] <== 1;

    for (var i = 0; i < N; i++) {
        isZero[i] = IsZero();
        isZero[i].in <== bytes[N-i-1];
        isZeroResult[i+1] <== isZero[i].out * isZeroResult[i];
    }
    
    var total = 0;
    
    for (var j = 1; j < N + 1; j++) {
        total = total + isZeroResult[j];
    }

    len <== N - total;
}

template RlpBalanceWithNonce0(N) {
    signal input num;
    signal output out[N + 1];
    signal output outLen;

    component decomp = ByteDecompose(N);
    decomp.num <== num;

    component length = GetRealByteLength(N);
    length.bytes <== decomp.bytes;

    component reversed = ReverseArray(N);
    reversed.bytes <== decomp.bytes;
    reversed.realByteLen <== length.len;

    component isSingleByte = LessThan(252);
    isSingleByte.in[0] <== num;
    isSingleByte.in[1] <== 128;

    component isZero = IsZero();
    isZero.in <== num;

    outLen <== (1 - isSingleByte.out) + length.len + isZero.out + 1;

    component firstRlpByteSelector = Mux1();
    firstRlpByteSelector.c[0] <== 0x80 + length.len;
    firstRlpByteSelector.c[1] <== num;
    firstRlpByteSelector.s <== isSingleByte.out;

    out[0] <== 0x80;
    out[1] <== firstRlpByteSelector.out + isZero.out * 0x80;
    for (var i = 1; i < N; i++) {
        out[i+1] <== (1 - isSingleByte.out) * reversed.out[i-1];
    }
}

template LeafCalculator() {
    signal input term[33];
    signal input term_len;
    signal input balance;
    signal output rlp_encoded[1024];
    signal output rlp_encoded_len;

    var storageAndCodeHashRlpLen = 66;
    signal storageAndCodeHashRlpEncoded[storageAndCodeHashRlpLen];
    storageAndCodeHashRlpEncoded[0] <== 160;
    storageAndCodeHashRlpEncoded[1] <== 86;
    storageAndCodeHashRlpEncoded[2] <== 232;
    storageAndCodeHashRlpEncoded[3] <== 31;
    storageAndCodeHashRlpEncoded[4] <== 23;
    storageAndCodeHashRlpEncoded[5] <== 27;
    storageAndCodeHashRlpEncoded[6] <== 204;
    storageAndCodeHashRlpEncoded[7] <== 85;
    storageAndCodeHashRlpEncoded[8] <== 166;
    storageAndCodeHashRlpEncoded[9] <== 255;
    storageAndCodeHashRlpEncoded[10] <== 131;
    storageAndCodeHashRlpEncoded[11] <== 69;
    storageAndCodeHashRlpEncoded[12] <== 230;
    storageAndCodeHashRlpEncoded[13] <== 146;
    storageAndCodeHashRlpEncoded[14] <== 192;
    storageAndCodeHashRlpEncoded[15] <== 248;
    storageAndCodeHashRlpEncoded[16] <== 110;
    storageAndCodeHashRlpEncoded[17] <== 91;
    storageAndCodeHashRlpEncoded[18] <== 72;
    storageAndCodeHashRlpEncoded[19] <== 224;
    storageAndCodeHashRlpEncoded[20] <== 27;
    storageAndCodeHashRlpEncoded[21] <== 153;
    storageAndCodeHashRlpEncoded[22] <== 108;
    storageAndCodeHashRlpEncoded[23] <== 173;
    storageAndCodeHashRlpEncoded[24] <== 192;
    storageAndCodeHashRlpEncoded[25] <== 1;
    storageAndCodeHashRlpEncoded[26] <== 98;
    storageAndCodeHashRlpEncoded[27] <== 47;
    storageAndCodeHashRlpEncoded[28] <== 181;
    storageAndCodeHashRlpEncoded[29] <== 227;
    storageAndCodeHashRlpEncoded[30] <== 99;
    storageAndCodeHashRlpEncoded[31] <== 180;
    storageAndCodeHashRlpEncoded[32] <== 33;
    storageAndCodeHashRlpEncoded[33] <== 160;
    storageAndCodeHashRlpEncoded[34] <== 197;
    storageAndCodeHashRlpEncoded[35] <== 210;
    storageAndCodeHashRlpEncoded[36] <== 70;
    storageAndCodeHashRlpEncoded[37] <== 1;
    storageAndCodeHashRlpEncoded[38] <== 134;
    storageAndCodeHashRlpEncoded[39] <== 247;
    storageAndCodeHashRlpEncoded[40] <== 35;
    storageAndCodeHashRlpEncoded[41] <== 60;
    storageAndCodeHashRlpEncoded[42] <== 146;
    storageAndCodeHashRlpEncoded[43] <== 126;
    storageAndCodeHashRlpEncoded[44] <== 125;
    storageAndCodeHashRlpEncoded[45] <== 178;
    storageAndCodeHashRlpEncoded[46] <== 220;
    storageAndCodeHashRlpEncoded[47] <== 199;
    storageAndCodeHashRlpEncoded[48] <== 3;
    storageAndCodeHashRlpEncoded[49] <== 192;
    storageAndCodeHashRlpEncoded[50] <== 229;
    storageAndCodeHashRlpEncoded[51] <== 0;
    storageAndCodeHashRlpEncoded[52] <== 182;
    storageAndCodeHashRlpEncoded[53] <== 83;
    storageAndCodeHashRlpEncoded[54] <== 202;
    storageAndCodeHashRlpEncoded[55] <== 130;
    storageAndCodeHashRlpEncoded[56] <== 39;
    storageAndCodeHashRlpEncoded[57] <== 59;
    storageAndCodeHashRlpEncoded[58] <== 123;
    storageAndCodeHashRlpEncoded[59] <== 250;
    storageAndCodeHashRlpEncoded[60] <== 216;
    storageAndCodeHashRlpEncoded[61] <== 4;
    storageAndCodeHashRlpEncoded[62] <== 93;
    storageAndCodeHashRlpEncoded[63] <== 133;
    storageAndCodeHashRlpEncoded[64] <== 164;
    storageAndCodeHashRlpEncoded[65] <== 112;

    component nonceAndBalanceRlp = RlpBalanceWithNonce0(21);
    nonceAndBalanceRlp.num <== balance;

    component concat = Concat(22, 66);
    concat.a <== nonceAndBalanceRlp.out;
    concat.aLen <== nonceAndBalanceRlp.outLen;
    concat.b <== storageAndCodeHashRlpEncoded;
    concat.bLen <== storageAndCodeHashRlpLen;

    signal account_rlp[92];
    signal account_rlp_len;
    signal term_rlp[36];
    signal term_rlp_len;

    account_rlp[0] <== 0xb8; 
    account_rlp[1] <== concat.outLen + 2;
    account_rlp[2] <== 0xf8; 
    account_rlp[3] <== concat.outLen;
    for(var i = 0; i < 88; i++) {
        account_rlp[i+4] <== concat.out[i];
    }
    account_rlp_len <== 4 + concat.outLen;

    term_rlp[0] <== 0xf7 + 1;
    term_rlp[1] <== (term_len + 1) + account_rlp_len;
    term_rlp[2] <== 0x80 + term_len;
    for(var i = 0; i < 33; i++) {
        term_rlp[i+3] <== term[i];
    }
    term_rlp_len <== term_len + 3;

    component leafCalc = Concat(36, 92);
    leafCalc.a <== term_rlp;
    leafCalc.aLen <== term_rlp_len;
    leafCalc.b <== account_rlp;
    leafCalc.bLen <== account_rlp_len;

    rlp_encoded_len <== leafCalc.outLen * 8;
    component decomp[128];
    for(var i = 0; i < 128; i++) {
        decomp[i] = Num2Bits(8);
        decomp[i].in <== leafCalc.out[i];
        for(var j = 0; j < 8; j++) {
            rlp_encoded[i*8+j] <== decomp[i].out[j];
        }
    }
}
