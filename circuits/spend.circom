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

// Computes the encrypted balance (coin) using the Poseidon2 hash function
// with the given `balance` and `burnkey`. Verifies that `withdrawnBalance` plus 
// `fee + remainingCoin` equals the encrypted balance, and includes both `fee` and 
// `receiverAddress` in the public commitment for added flexibility.
//
// Example:
//   balance:           1000
//   burnKey:           123456
//   coin:              Poseidon2(123456, 1000)
//   withdrawnBalance:  200
//   remainingCoin:     Poseidon2(123456, 750)
//   fee:               50
//   receiverAddress:   0x1234567890abcdef1234567890abcdef
template Spend(maxAmountBytes) {
    signal input burnKey;
    signal input balance;
    signal input withdrawnBalance;
    signal input receiverAddress;

    signal output commitment;
    signal input fee;


    assert(maxAmountBytes <= 31); // To avoid field overflows
    AssertBits(maxAmountBytes * 8)(fee);
    AssertBits(maxAmountBytes * 8)(withdrawnBalance);
    AssertBits(160)(receiverAddress);
    AssertGreaterEqThan(maxAmountBytes * 8)(balance, withdrawnBalance + fee);
    signal feeBytes[32] <== Num2BigEndianBytes(32)(fee);
    signal coin <== Poseidon(2)([burnKey, balance]);
    signal remainingCoin <== Poseidon(2)([burnKey, balance - withdrawnBalance - fee]);

    signal coinBytes[32] <== Num2BigEndianBytes(32)(coin);
    signal withdrawnBalanceBytes[32] <== Num2BigEndianBytes(32)(withdrawnBalance);
    signal remainingCoinBytes[32] <== Num2BigEndianBytes(32)(remainingCoin);
    signal receiverAddressBytes[32] <== Num2BigEndianBytes(32)(receiverAddress);
    commitment <== PublicCommitment(5)(
        [coinBytes, withdrawnBalanceBytes, remainingCoinBytes, feeBytes, receiverAddressBytes]
    );
}