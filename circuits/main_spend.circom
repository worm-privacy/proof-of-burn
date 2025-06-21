pragma circom 2.2.2;

include "./spend.circom";

component main {public [withdrawnBalance]} = Spend(200);