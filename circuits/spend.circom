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
//   coin:              MiMC(123456, 1000)
//   withdrawnBalance:  200
//   remainingCoin:     MiMC(123456, 800)
template Spend(maxAmountBytes) {
    signal input burnKey;
    signal input balance;
    signal input withdrawnBalance;

    signal output coin;
    signal output remainingCoin;

    assert(maxAmountBytes <= 31); // To avoid field overflows

    AssertGreaterEqThan(maxAmountBytes * 8)(balance, withdrawnBalance);

    coin <== Hasher()(burnKey, balance);
    remainingCoin <== Hasher()(burnKey, balance - withdrawnBalance);
}