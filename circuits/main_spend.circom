pragma circom 2.2.2;

include "./spend.circom";

// Maximum 31 bytes for amounts to avoid field overflows
component main = Spend(31);