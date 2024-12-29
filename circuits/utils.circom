pragma circom 2.1.9;

include "../circomlib/circuits/mimcsponge.circom";
include "../circomlib/circuits/bitify.circom";
include "poseidon2.circom";

// Computes MiMC([left, right])
template HashLeftRightMiMC() {
    signal input left;
    signal input right;
    signal output hash;

    component hasher = MiMCSponge(2, 220, 1);
    hasher.ins[0] <== left;
    hasher.ins[1] <== right;
    hasher.k <== 0;
    hash <== hasher.outs[0];
}

// Computes Poseidon2
template HashLeftRightPoseidon2() {
    signal input left;
    signal input right;
    signal output hash;

    component hasher = Poseidon2(3, 1);
    hasher.inputs[0] <== left;
    hasher.inputs[1] <== right;
    hasher.inputs[2] <== 1;
    hash <== hasher.out[0];
}

// if s == 0 returns [in[0], in[1]]
// if s == 1 returns [in[1], in[0]]
template DualMux() {
    signal input in[2];
    signal input s;
    signal output out[2];

    s * (1 - s) === 0;
    out[0] <== (in[1] - in[0])*s + in[0];
    out[1] <== (in[0] - in[1])*s + in[1];
}


// Verifies that merkle proof is correct for given merkle root and a leaf
// pathIndices input is an array of 0/1 selectors telling whether given pathElement is on the left or right side of merkle path
template MerkleTreeCheckerMiMC(levels) {
    signal input leaf;
    signal input root;
    signal input pathElements[levels];
    signal input pathIndices[levels];

    component selectors[levels];
    component hashers[levels];

    for (var i = 0; i < levels; i++) {
        selectors[i] = DualMux();
        selectors[i].in[0] <== i == 0 ? leaf : hashers[i - 1].hash;
        selectors[i].in[1] <== pathElements[i];
        selectors[i].s <== pathIndices[i];

        hashers[i] = HashLeftRightMiMC();
        hashers[i].left <== selectors[i].out[0];
        hashers[i].right <== selectors[i].out[1];
    }
    root === hashers[levels - 1].hash;
}

// Verifies that merkle proof is correct for given merkle root and a leaf
// pathIndices input is an array of 0/1 selectors telling whether given pathElement is on the left or right side of merkle path
template MerkleTreeCheckerPoseidon2(levels) {
    signal input leaf;
    signal input root;
    signal input pathElements[levels];
    signal input pathIndices[levels];

    component selectors[levels];
    component hashers[levels];

    for (var i = 0; i < levels; i++) {
        selectors[i] = DualMux();
        selectors[i].in[0] <== i == 0 ? leaf : hashers[i - 1].hash;
        selectors[i].in[1] <== pathElements[i];
        selectors[i].s <== pathIndices[i];

        hashers[i] = HashLeftRightPoseidon2();
        hashers[i].left <== selectors[i].out[0];
        hashers[i].right <== selectors[i].out[1];
    }
    root === hashers[levels - 1].hash;
}

template Sigma() {
    signal input in;
    signal output out;

    signal in2;
    signal in4;

    in2 <== in*in;
    in4 <== in2*in2;

    out <== in4*in;
}

template Sum(t) {
    signal input in[t];
    signal output out;
    var sum = 0;
    for (var i = 0; i < t; i++) {
        sum += in[i];
    }
    out <== sum;
}

template Swap(t, from, to) {
    signal input in[t];

    signal output out[t];

    var current_stage[t];

    for (var i = 0; i < t; i++) {
        current_stage[i] = in[i];
    }

    current_stage[to] = in[from];
    current_stage[from] = in[to];

    for (var i = 0; i < t; i++) {
        out[i] <== current_stage[i];
    }
}

template AddRC(t, rc) {
    signal input in[t];
    signal output out[t];

    for (var i = 0; i < t; i++) {
        out[i] <== in[i] + rc[i]; 
    }
}

template Rotate_right(t) {
    signal input in[t];
    signal output out[t];

    out[0] <== in[t - 1];
    for (var i = 1; i < t; i++){
        out[i] <== in[i - 1];
    }
}

template Rotate_left(t) {
    signal input in[t];
    signal output out[t];

    out[t - 1] <== in[0];
    for (var i = 0; i < t - 1; i++){
        out[i] <== in[i + 1];
    }
}

template DotProduct(t) {
    signal input in1[t];
    signal input in2[t];
    signal output out;

    signal sum[t];

    sum[0] <== in1[0] * in2[0];
    for (var i = 1; i < t; i++) {
        sum[i] <== sum[i-1] + in1[i] * in2[i];
    }

    out <== sum[t-1];
}

template Pow5() {
    signal input in;
    signal output out;
    signal in2;
    signal in4;
    in2 <== in*in;
    in4 <== in2*in2;
    out <== in4*in;
}

template InvPow5() {
    signal input in;
    signal output out;
    component pow5;
    pow5 = Pow5();
    pow5.in <-- in ** 17510594297471420177797124596205820070838691520332827474958563349260646796493; // inv 5
    pow5.out === in;
    out <== pow5.in;
}