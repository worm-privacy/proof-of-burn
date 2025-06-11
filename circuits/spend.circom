pragma circom 2.1.5;

include "./utils/keccak/keccak.circom";
include "./utils/substring_finder.circom";
include "./utils/hasher.circom";
include "./utils/padding.circom";
include "./utils/hashbytes.circom";
include "./utils/concat.circom";
include "./utils/rlp.circom";

template Spend() {
    signal input balance;
    signal input salt;
    signal output coin;

    component coinHasher = Hasher();
    coinHasher.left <== balance;
    coinHasher.right <== salt;
    coin <== coinHasher.hash;

    signal input withdrawnBalance;
    signal input remainingCoinSalt;
    signal output remainingCoin;

    component sufficientBalanceChecker = GreaterEqThan(252);
    sufficientBalanceChecker.in[0] <== balance;
    sufficientBalanceChecker.in[1] <== withdrawnBalance;
    sufficientBalanceChecker.out === 1;

    component remainingCoinHasher = Hasher();
    remainingCoinHasher.left <== balance - withdrawnBalance;
    remainingCoinHasher.right <== remainingCoinSalt;
    remainingCoin <== remainingCoinHasher.hash;
}

component main {public [withdrawnBalance]} = Spend();