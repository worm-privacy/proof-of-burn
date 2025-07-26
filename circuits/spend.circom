//   __        _____  ____  __  __ 
//   \ \      / / _ \|  _ \|  \/  |
//    \ \ /\ / / | | | |_) | |\/| |
//     \ V  V /| |_| |  _ <| |  | |
//      \_/\_/  \___/|_| \_\_|  |_|
//

pragma circom 2.2.2;

include "./utils/assert.circom";
include "./utils/hasher.circom";
include "./utils/utils.circom";
include "./utils/commit.circom";

// Computes the encrypted balance (coin) using the Poseidon2 hash function 
// with the given `balance` and `salt`. It then checks if the sum of 
// `withdrawnBalance` and `remainingCoin` matches the encrypted balance.
//
// Example:
//   balance:           1000
//   burnKey:           123456
//   coin:              Poseidon2(123456, 1000)
//   withdrawnBalance:  200
//   remainingCoin:     Poseidon2(123456, 800)
template Spend(maxAmountBytes) {
    signal input burnKey;
    signal input balance;
    signal input withdrawnBalance;

    signal output commitment;

    assert(maxAmountBytes <= 31); // To avoid field overflows

    AssertGreaterEqThan(maxAmountBytes * 8)(balance, withdrawnBalance);

    signal coin <== Hasher()(burnKey, balance);
    signal remainingCoin <== Hasher()(burnKey, balance - withdrawnBalance);

    signal coinBytes[32] <== Num2BigEndianBytes(32)(coin);
    signal withdrawnBalanceBytes[32] <== Num2BigEndianBytes(32)(withdrawnBalance);
    signal remainingCoinBytes[32] <== Num2BigEndianBytes(32)(remainingCoin);
    commitment <== PublicCommitment(3)(
        [coinBytes, withdrawnBalanceBytes, remainingCoinBytes]
    );
}