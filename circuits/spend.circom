//   __        _____  ____  __  __ 
//   \ \      / / _ \|  _ \|  \/  |
//    \ \ /\ / / | | | |_) | |\/| |
//     \ V  V /| |_| |  _ <| |  | |
//      \_/\_/  \___/|_| \_\_|  |_|
//

pragma circom 2.2.2;

include "./utils/keccak/keccak.circom";
include "./utils/substring_finder.circom";
include "./utils/hasher.circom";
include "./utils/padding.circom";
include "./utils/hashbytes.circom";
include "./utils/concat.circom";
include "./utils/rlp.circom";

// Computes the encrypted balance (coin) using the MiMC hash function 
// with the given `balance` and `salt`. It then checks if the sum of 
// `withdrawnBalance` and `remainingCoin` matches the encrypted balance.
//
// Example:
//   balance:           1000
//   salt:              123456
//   coin:              MiMC(1000, 123456)
//   withdrawnBalance:  200
//   remainingCoinSalt: 234567
//   remainingCoin:     MiMC(800, 234567)
template Spend() {
    signal input balance;
    signal input salt;
    signal input withdrawnBalance;
    signal input remainingCoinSalt;

    signal output coin;
    signal output remainingCoin;

    component coinHasher = Hasher();
    coinHasher.left <== balance;
    coinHasher.right <== salt;
    coin <== coinHasher.hash;

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