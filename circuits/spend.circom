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

// Computes the encrypted balance (coin) using the Poseidon3 hash function
// with the given `balance` and `burnKey`. Verifies that `withdrawnBalance` plus 
// `fee + remainingCoin` equals the encrypted balance, and includes both `fee` and 
// `receiverAddress` in the public commitment to enforce them.
//
// Example:
//   balance:           1000
//   withdrawnBalance:  200
//   broadcasterFeeFee: 50
//   burnKey:           123456
//   coin:              Poseidon3(POSEIDON_COIN_PREFIX, 123456, 1000)
//   remainingCoin:     Poseidon3(POSEIDON_COIN_PREFIX, 123456, 750)
//   receiverAddress:   0x1234567890abcdef1234567890abcdef
//
// Reviewers:
//   Keyvan: Ok
//
template Spend(maxAmountBytes) {
    signal input burnKey;
    signal input balance;
    signal input withdrawnBalance;
    signal input receiverAddress;
    signal input broadcasterFee;

    signal output commitment;

    assert(maxAmountBytes <= 31); // To avoid field overflows
    AssertBits(maxAmountBytes * 8)(broadcasterFee);
    AssertBits(maxAmountBytes * 8)(withdrawnBalance);
    AssertBits(160)(receiverAddress);
    AssertGreaterEqThan(maxAmountBytes * 8)(balance, withdrawnBalance + broadcasterFee);

    signal coin <== Poseidon(3)([POSEIDON_COIN_PREFIX(), burnKey, balance]);
    signal remainingCoin <== Poseidon(3)([POSEIDON_COIN_PREFIX(), burnKey, balance - withdrawnBalance - broadcasterFee]);

    signal coinBytes[32] <== Num2BigEndianBytes(32)(coin);
    signal withdrawnBalanceBytes[32] <== Num2BigEndianBytes(32)(withdrawnBalance);
    signal remainingCoinBytes[32] <== Num2BigEndianBytes(32)(remainingCoin);
    signal broadcasterFeeBytes[32] <== Num2BigEndianBytes(32)(broadcasterFee);
    signal receiverAddressBytes[32] <== Num2BigEndianBytes(32)(receiverAddress);
    commitment <== PublicCommitment(5)(
        [coinBytes, withdrawnBalanceBytes, remainingCoinBytes, broadcasterFeeBytes, receiverAddressBytes]
    );
}