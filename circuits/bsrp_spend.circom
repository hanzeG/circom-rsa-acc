pragma circom 2.1.6;

include "bsrp_bigInt.circom";
include "../circomlib/circuits/poseidon.circom";
include "utils.circom";

template Spend(CHUNK_SIZE, CHUNK_NUMBER, BITS, DEPTH) {
    signal input N[CHUNK_NUMBER];        // Private signal: modulus N
    signal input witness[CHUNK_NUMBER];  // Private signal: witness
    signal input secret;                 // Private signal: secret exponent
    signal input commitment[CHUNK_NUMBER]; // Private signal: commitment

    signal input nullifierHash;  // Public signal: nullifier hash

    // Merkle tree operations
    signal input root;                 // Public signal: Merkle tree root
    signal input pathElements[DEPTH];  // Merkle tree path elements
    signal input pathIndices[DEPTH];   // Merkle tree path indices

    signal input receipt; // Not used in computations, included for integrity checks
    signal input relayer;  // Not used in computations, included for integrity checks
    signal input fee;      // Not used in computations, included for integrity checks
    signal input refund;   // Not used in computations, included for integrity checks

    signal output isSpent; // Output signal indicating a successful spend

    // Check leaf existence in the Merkle tree
    component mtc = MerkleTreeChecker(DEPTH);
    // Calculate the commitment hash
    component mimc = HashLeftRight();
    mimc.left <== commitment[0];
    mimc.right <== commitment[1];

    mtc.leaf <== mimc.hash;
    mtc.root <== root;
    for (var i = 0; i < DEPTH; i++) {
        mtc.pathElements[i] <== pathElements[i];
        mtc.pathIndices[i] <== pathIndices[i];
    }

    // Verify witness for RSA accumulator membership
    component vw = VerifyWitness(CHUNK_SIZE, CHUNK_NUMBER, BITS);
    for (var i = 0; i < CHUNK_NUMBER; i++) {
        vw.modulus[i] <== N[i];
        vw.witness[i] <== witness[i];
        vw.target[i] <== commitment[i];
    }
    vw.secret <== secret;
    vw.verification === CHUNK_NUMBER;

    // Compute nullifier hash using Poseidon
    component ph = Poseidon(2);
    ph.inputs[0] <== witness[0];
    ph.inputs[1] <== witness[1];
    nullifierHash === ph.out;

    // Add hidden signals to ensure tampering with receipt or fee invalidates the SNARK proof
    // While not strictly necessary, these constraints provide additional security
    // Squares are used to prevent the optimizer from removing these constraints
    signal receiptSquare;
    signal feeSquare;
    signal relayerSquare;
    signal refundSquare;
    receiptSquare <== receipt * receipt;
    feeSquare <== fee * fee;
    relayerSquare <== relayer * relayer;
    refundSquare <== refund * refund;

    // If a valid proof is generated, all constraints above are satisfied; set isSpent to 1
    isSpent <== 1;
}