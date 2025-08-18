pragma circom 2.2.2;

function POSEIDON_PREFIX() {
    // int.from_bytes(web3.Web3.keccak(b"EIP-7503"), byteorder='big') % P
    return 5265656504298861414514317065875120428884240036965045859626767452974705356670;
}
function POSEIDON_BURN_ADDRESS_PREFIX() {
    return POSEIDON_PREFIX() + 0;
}
function POSEIDON_NULLIFIER_PREFIX() {
    return POSEIDON_PREFIX() + 1;
}
function POSEIDON_COIN_PREFIX() {
    return POSEIDON_PREFIX() + 2;
}