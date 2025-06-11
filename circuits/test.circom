
        pragma circom 2.2.2;
        
        include "utils/concat.circom";
        include "utils/hasher.circom";
        include "utils/leaf.circom";
        include "utils/rlp.circom";
        include "utils/selector.circom";
        include "utils/substring_finder.circom";
        include "utils/utils.circom";
        
        component main = SubstringCheck(10, 3);