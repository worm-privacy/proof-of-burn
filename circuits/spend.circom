//   __        _____  ____  __  __ 
//   \ \      / / _ \|  _ \|  \/  |
//    \ \ /\ / / | | | |_) | |\/| |
//     \ V  V /| |_| |  _ <| |  | |
//      \_/\_/  \___/|_| \_\_|  |_|
//

pragma circom 2.2.2;

include "./circomlib/circuits/poseidon.circom";
include "./utils/assert.circom";
include "./utils/convert.circom";
include "./utils/public_commitment.circom";
include "./utils/constants.circom";
// Computes the encrypted balance (coin) using the Poseidon2 hash function
// with the given `balance` and `burnKey`. Verifies that `withdrawnBalance` plus 
// `fee + remainingCoin` equals the encrypted balance, and includes both `fee` and 
// `receiverAddress` in the public commitment to enforce them.
//
// Example:
//   balance:           1000
//   withdrawnBalance:  200
//   fee:               50
//   burnKey:           123456
//   coin:              Poseidon2(123456, 1000)
//   remainingCoin:     Poseidon2(123456, 750)
//   receiverAddress:   0x1234567890abcdef1234567890abcdef
template Spend(maxAmountBytes) {
    signal input burnKey;
    signal input balance;
    signal input withdrawnBalance;
    signal input receiverAddress;
    signal input fee;

    signal output commitment;


    assert(maxAmountBytes <= 31); // To avoid field overflows
    AssertBits(maxAmountBytes * 8)(fee);
    AssertBits(maxAmountBytes * 8)(withdrawnBalance);
    AssertBits(160)(receiverAddress);
    AssertGreaterEqThan(maxAmountBytes * 8)(balance, withdrawnBalance + fee);
    signal coin <== Poseidon(3)([POSEIDON_COIN_PREFIX(), burnKey, balance]);
    signal coinBytes[32] <== Num2BigEndianBytes(32)(coin);
    signal withdrawnBalanceBytes[32] <== Num2BigEndianBytes(32)(withdrawnBalance);
    signal remainingCoin <== Poseidon(3)([POSEIDON_COIN_PREFIX(), burnKey, balance - withdrawnBalance - fee]);
    signal remainingCoinBytes[32] <== Num2BigEndianBytes(32)(remainingCoin);
    signal feeBytes[32] <== Num2BigEndianBytes(32)(fee);
    signal receiverAddressBytes[32] <== Num2BigEndianBytes(32)(receiverAddress);
    commitment <== PublicCommitment(5)(
        [coinBytes, withdrawnBalanceBytes, remainingCoinBytes, feeBytes, receiverAddressBytes]
    );
}