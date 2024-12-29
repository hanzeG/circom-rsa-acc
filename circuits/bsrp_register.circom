pragma circom 2.1.6;

include "bsrp_bigInt.circom";

// User register by p * q = N
template Register(CHUNK_SIZE, CHUNK_NUMBER) {
    signal input p[CHUNK_NUMBER]; // private signal
    signal input q[CHUNK_NUMBER]; // private signal
    
    signal output N[CHUNK_NUMBER * 2];  // public signal

    // TODO: primality check for p, q

    component bm = BigMult(CHUNK_SIZE, CHUNK_NUMBER);

    for (var i = 0; i < CHUNK_NUMBER; i++) {
        bm.a[i] <== p[i];
        bm.b[i] <== q[i];
    }

    for (var i = 0; i < CHUNK_NUMBER * 2; i++) {
        N[i] <== bm.out[i];
    }
}