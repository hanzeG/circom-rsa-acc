pragma circom 2.1.6;

include "utils.circom";
include "poseidon2.circom";

template Spend(CHUNK_SIZE, CHUNK_NUMBER, DEPTH) {
    signal input message[CHUNK_NUMBER]; // Private signal: decrypted message
    signal input messageHash; // Public signal: message hash
    signal input inv[CHUNK_NUMBER]; // Private signal: inv
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
    component ph0 = MerkleTreeCheckerPoseidon2(DEPTH);
    ph0.leaf <== messageHash;
    ph0.root <== root;
    for (var i = 0; i < DEPTH; i++) {
        ph0.pathElements[i] <== pathElements[i];
        ph0.pathIndices[i] <== pathIndices[i];
    }

    // Verify the preimage of message hash using Poseidon2
    component ph1 = Poseidon2(3,1);
    ph1.inputs[0] <== message[0];
    ph1.inputs[1] <== 1;
    ph1.inputs[2] <== 1;
    messageHash === ph1.out[0];

    // Compute nullifier hash using Poseidon2
    component ph2 = Poseidon2(3,1);
    ph2.inputs[0] <== inv[0];
    ph2.inputs[1] <== message[0];
    ph2.inputs[2] <== 1;
    nullifierHash === ph2.out[0];

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