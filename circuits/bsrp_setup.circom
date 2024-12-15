pragma circom 2.1.6;

include "bsrp_bigInt.circom";

// Alice's setup for stealth address (targetA, targetN), with secret
template Setup(CHUNK_SIZE, CHUNK_NUMBER, BITS) {
    signal input g[CHUNK_NUMBER]; // public signal
    signal input N[CHUNK_NUMBER]; // public signal
    // signal input p[CHUNK_NUMBER]; // private signal
    // signal input q[CHUNK_NUMBER]; // private signal

    signal input secret; // private signal
    
    signal output A[CHUNK_NUMBER];  // public signal

    // TODO: primality check for secret, p, q, p*q=N, g

    // pow mod to generate A
    component pm = PowerModAnyExp(CHUNK_SIZE, CHUNK_NUMBER, BITS);

    for (var i = 0; i < CHUNK_NUMBER; i++) {
        pm.base[i] <== g[i];
        pm.modulus[i] <== N[i];
    }

    pm.exp <== secret;

    for (var i = 0; i < CHUNK_NUMBER; i++) {
        A[i] <== pm.out[i];
    }
}