pragma circom 2.1.6;

include "bsrp_bigInt.circom";
include "bsrp_spend.circom";
include "poseidon2.circom";

// Bob deposit money (with their secret message) to generate utxos (ciphertext)
// for Alice's stealth address (targetN)
template ExTransfer(CHUNK_SIZE, CHUNK_NUMBER, BITS) {
    signal input target_N[CHUNK_NUMBER]; // private signal
    signal input secret[CHUNK_NUMBER]; // private signal (plaintext, secret message)
    
    signal input exp; // public signal
    
    signal output out[CHUNK_NUMBER + 1];  // public signal (ciphertext[CHUNK_NUMBER] & message hash/ commitment)

    // pow mod to generate ciphertext
    component pm = PowerModAnyExp(CHUNK_SIZE, CHUNK_NUMBER, BITS);

    for (var i = 0; i < CHUNK_NUMBER; i++) {
        pm.base[i] <== secret[i];
        pm.modulus[i] <== target_N[i];
    }
    pm.exp <== exp;
    
    for (var i = 0; i < CHUNK_NUMBER; i++) {
        out[i] <== pm.out[i];
    }

    // Compute message (secret) hash (commitment) using Poseidon2
    component ph = Poseidon2(3,1);
    ph.inputs[0] <== secret[0];
    ph.inputs[1] <== 1;
    ph.inputs[2] <== 1;
    out[CHUNK_NUMBER] <== ph.out[0];
}

// Bob spend their own utxo to mint new one for Alice (no new external deposit)
template InTransfer(CHUNK_SIZE, CHUNK_NUMBER, BITS, DEPTH) {
    signal input mint_message[CHUNK_NUMBER]; // private signal
    signal input mint_N[CHUNK_NUMBER]; // private signal
    signal input mint_exp; // public signal: exp
    
    // spend template inputs
    signal input spend_message[CHUNK_NUMBER];  // Private signal: decrypted message
    signal input spend_inv[CHUNK_NUMBER]; // Private signal: inv
    signal input spend_messageHash;  // Public signal: message hash (commitment)
    signal input spend_nullifierHash;  // Public signal: nullifier hash
    
    // Merkle tree operations
    signal input root;                 // Public signal: Merkle tree root
    signal input pathElements[DEPTH];  // Merkle tree path elements
    signal input pathIndices[DEPTH];   // Merkle tree path indices
    signal input receipt; // Not used in computations, included for integrity checks
    signal input relayer;  // Not used in computations, included for integrity checks
    signal input fee;      // Not used in computations, included for integrity checks
    signal input refund;   // Not used in computations, included for integrity checks
    
    signal output out[CHUNK_NUMBER + 1];  // public signal, new ciphertext[CHUNK_NUMBER] and commitment for UTXO

    // spend old UTXO
    component sp = Spend(CHUNK_SIZE, CHUNK_NUMBER, DEPTH);
    sp.messageHash <== spend_messageHash;
    sp.nullifierHash <== spend_nullifierHash;
    for (var i = 0; i < CHUNK_NUMBER; i++) {
        sp.message[i] <== spend_message[i];
        sp.inv[i] <== spend_inv[i];
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

    // pow mod to generate new commitment (ciphertext)
    component pm = PowerModAnyExp(CHUNK_SIZE, CHUNK_NUMBER, BITS);

    for (var i = 0; i < CHUNK_NUMBER; i++) {
        pm.base[i] <== mint_message[i];
        pm.modulus[i] <== mint_N[i];
    }
    pm.exp <== mint_exp;
    
    for (var i = 0; i < CHUNK_NUMBER; i++) {
        out[i] <== pm.out[i];
    }

    // Compute message (secret) hash (commitment) using Poseidon2
    component ph = Poseidon2(3,1);
    ph.inputs[0] <== mint_message[0];
    ph.inputs[1] <== 1;
    ph.inputs[2] <== 1;
    out[CHUNK_NUMBER] <== ph.out[0];
}