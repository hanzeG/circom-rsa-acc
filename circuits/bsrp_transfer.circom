pragma circom 2.1.6;

include "bsrp_bigInt.circom";

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


// Bob spend their own utxo to mint new one for Alice (no new deposit)
// template InTransfer(CHUNK_SIZE, CHUNK_NUMBER, BITS) {
//     signal input targetA[CHUNK_NUMBER]; // private signal
//     signal input targetN[CHUNK_NUMBER]; // private signal
//     signal input secret; // private signal
    
//     signal output newA[CHUNK_NUMBER];  // public signal

//     // todo: primality check for secret
    

//     // pow mod to generate new A (commitment)
//     component pm = PowerModAnyExp(CHUNK_SIZE, CHUNK_NUMBER, BITS);

//     for (var i = 0; i < CHUNK_NUMBER; i++) {
//         pm.base[CHUNK_NUMBER] <== targetA[CHUNK_NUMBER];
//         pm.modulus[CHUNK_NUMBER] <== targetN[CHUNK_NUMBER];
//     }
//     pm.exp <== secret;
    
//     for (var i = 0; i < CHUNK_NUMBER; i++) {
//         newA[i] <== pm.out[i];
//     }
// }