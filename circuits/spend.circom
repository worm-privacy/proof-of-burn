//   __        _____  ____  __  __ 
//   \ \      / / _ \|  _ \|  \/  |
//    \ \ /\ / / | | | |_) | |\/| |
//     \ V  V /| |_| |  _ <| |  | |
//      \_/\_/  \___/|_| \_\_|  |_|
//

pragma circom 2.2.2;

include "./utils/assert.circom";
include "./utils/hasher.circom";

// Computes the encrypted balance (coin) using the MiMC hash function 
// with the given `balance` and `salt`. It then checks if the sum of 
// `withdrawnBalance` and `remainingCoin` matches the encrypted balance.
//
// Example:
//   balance:           1000
//   burnKey:           123456
//   coin:              MiMC(1000, 123456)
//   withdrawnBalance:  200
//   remainingCoin:     MiMC(800, 123456)
template Spend(maxAmountBits) {
    signal input balance;
    signal input burnKey;
    signal input withdrawnBalance;

    signal output coin;
    signal output remainingCoin;

    AssertGreaterEqThan(maxAmountBits)(balance, withdrawnBalance);

    coin <== Hasher()(balance, burnKey);
    remainingCoin <== Hasher()(balance - withdrawnBalance, burnKey);
}

component main {public [withdrawnBalance]} = Spend(200);