pragma circom 2.1.6;

include "bsrp_bigInt.circom";
include "bsrp_spend.circom";

// Bob deposit money (with their secret) to generate utxos for Alice's stealth address (targetA, targetN)
template ExTransfer(CHUNK_SIZE, CHUNK_NUMBER, BITS) {
    signal input targetA[CHUNK_NUMBER]; // private signal
    signal input targetN[CHUNK_NUMBER]; // private signal

    signal input secret; // private signal
    
    signal output newA[CHUNK_NUMBER];  // public signal

    // todo: primality check for secret
    

    // pow mod to generate new A (commitment)
    component pm = PowerModAnyExp(CHUNK_SIZE, CHUNK_NUMBER, BITS);

    for (var i = 0; i < CHUNK_NUMBER; i++) {
        pm.base[i] <== targetA[i];
        pm.modulus[i] <== targetN[i];
    }
    pm.exp <== secret;
    
    for (var i = 0; i < CHUNK_NUMBER; i++) {
        newA[i] <== pm.out[i];
    }
}


// Bob spend their own utxo to mint new one for Alice (no new external deposit)
template InTransfer(CHUNK_SIZE, CHUNK_NUMBER, BITS, DEPTH) {
    signal input mintM[CHUNK_NUMBER]; // private signal
    signal input mintN[CHUNK_NUMBER]; // private signal
    signal input mintE; // private signal
    
    // spend template inputs
    signal input spendN[CHUNK_NUMBER];        // Private signal: modulus N
    signal input spendM[CHUNK_NUMBER];  // Private signal: witness
    signal input spendE;                 // Private signal: secret exponent
    signal input spendC[CHUNK_NUMBER]; // Private signal: commitment
    signal input nullifierHash;  // Public signal: nullifier hash
    // Merkle tree operations
    signal input root;                 // Public signal: Merkle tree root
    signal input pathElements[DEPTH];  // Merkle tree path elements
    signal input pathIndices[DEPTH];   // Merkle tree path indices
    signal input receipt; // Not used in computations, included for integrity checks
    signal input relayer;  // Not used in computations, included for integrity checks
    signal input fee;      // Not used in computations, included for integrity checks
    signal input refund;   // Not used in computations, included for integrity checks
    
    signal output mintC[CHUNK_NUMBER];  // public signal

    // spend old UTXO
    component sp = Spend(CHUNK_SIZE, CHUNK_NUMBER, BITS, DEPTH);
    sp.secret <== spendE;
    sp.nullifierHash <== nullifierHash;
    for (var i = 0; i < CHUNK_NUMBER; i++) {
        sp.N[i] <== spendN[i];
        sp.witness[i] <== spendM[i];
        sp.commitment[i] <== spendC[i];
    }
    sp.root <== root;
    sp.receipt <== receipt;
    sp.relayer <== relayer;
    sp.fee <== fee;
    sp.refund <== refund;
    for (var i = 0; i < DEPTH; i++) {
        sp.pathElements[i] <== pathElements[i];
        sp.pathIndices[i] <== pathIndices[i];
    }

    sp.isSpent === 1;

    // pow mod to generate new A (commitment)
    component pm = PowerModAnyExp(CHUNK_SIZE, CHUNK_NUMBER, BITS);

    for (var i = 0; i < CHUNK_NUMBER; i++) {
        pm.base[i] <== mintM[i];
        pm.modulus[i] <== mintN[i];
    }
    pm.exp <== mintE;
    
    for (var i = 0; i < CHUNK_NUMBER; i++) {
        mintC[i] <== pm.out[i];
    }
}