pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";

template HashCheck() {
    signal input secret;
    signal output hash;

    component poseidon = Poseidon(1);
    poseidon.inputs[0] <== secret;
    hash <== poseidon.out;
}

component main = HashCheck();