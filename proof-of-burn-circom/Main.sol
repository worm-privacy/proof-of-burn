contract Main {
    constructor() {
    }
    function mint() public {
        uint256 bal = 123;
        uint256 nul = 234;
        keccak256(abi.encodePacked(blockhash(block.number), bal, nul));
    }
}