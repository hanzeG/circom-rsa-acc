pragma circom 2.1.6;

include "bigInt.circom";

// SquareAndMultiply template
template SquareAndMultiply(CHUNK_SIZE, CHUNK_NUMBER) {
    signal input current[CHUNK_NUMBER];
    signal input base[CHUNK_NUMBER];
    signal input modulus[CHUNK_NUMBER];
    signal input bit; // Current exponent bit (0 or 1)
    signal output next[CHUNK_NUMBER];

    // Perform square operation: current^2 mod modulus
    component square = BigMultModP(CHUNK_SIZE, CHUNK_NUMBER);
    square.p <== modulus;
    square.a <== current;
    square.b <== current;

    // Perform conditional multiplication: (current^2 * base) mod modulus
    component mul = BigMultModP(CHUNK_SIZE, CHUNK_NUMBER);
    mul.p <== modulus;
    mul.a <== square.out;
    mul.b <== base;

    // Use selector signals for conditional selection
    signal sel_square[CHUNK_NUMBER];
    signal sel_mul[CHUNK_NUMBER];

    for (var j = 0; j < CHUNK_NUMBER; j++) {
        // Conditional selection constraint
        sel_square[j] <== (1 - bit) * square.out[j];
        sel_mul[j] <== bit * mul.out[j];
        next[j] <== sel_square[j] + sel_mul[j];
    }
}

// PowerMod with any bigInt template
template PowerModAnyExp(CHUNK_SIZE, CHUNK_NUMBER, BITS) {
    signal input base[CHUNK_NUMBER];
    signal input exp;
    signal input modulus[CHUNK_NUMBER];
    
    signal output out[CHUNK_NUMBER];
    
    // Initialize current0 to 1
    signal current0[CHUNK_NUMBER];
    current0[0] <== 1;
    for (var j = 1; j < CHUNK_NUMBER; j++) {
        current0[j] <== 0;
    }

    component nb = Num2Bits(BITS);
    nb.in <== exp;

    // Define an array of step components
    component step[BITS];

    for (var i = 0; i < BITS; i++) {
        step[i] = SquareAndMultiply(CHUNK_SIZE, CHUNK_NUMBER);
        
        // Assign input signals for each step
        for (var j = 0; j < CHUNK_NUMBER; j++) {
            if (i == 0) {
                // For the first step, current is current0
                step[i].current[j] <== current0[j];
            } else {
                // For other steps, current is the next of the previous step
                step[i].current[j] <== step[i-1].next[j];
            }
            step[i].base[j] <== base[j];
            step[i].modulus[j] <== modulus[j];
        }

        // Assign the current exponent bit
        step[i].bit <== nb.out[BITS - i - 1];
    }

    // Final output is assigned from the next of the last step
    for (var j = 0; j < CHUNK_NUMBER; j++) {
        out[j] <== step[BITS - 1].next[j];
    }
}

// PowerMod with any bigInt template with exp bits array, for Rabin-Miller check
template PowerModAnyExpBits(CHUNK_SIZE, CHUNK_NUMBER, BITS) {
    signal input base[CHUNK_NUMBER];
    signal input exp[BITS];
    signal input modulus[CHUNK_NUMBER];
    
    signal output out[CHUNK_NUMBER];
    
    // Initialize current0 to 1
    signal current0[CHUNK_NUMBER];
    current0[0] <== 1;
    for (var j = 1; j < CHUNK_NUMBER; j++) {
        current0[j] <== 0;
    }

    // Define an array of step components
    component step[BITS];

    for (var i = 0; i < BITS; i++) {
        step[i] = SquareAndMultiply(CHUNK_SIZE, CHUNK_NUMBER);
        
        // Assign input signals for each step
        for (var j = 0; j < CHUNK_NUMBER; j++) {
            if (i == 0) {
                // For the first step, current is current0
                step[i].current[j] <== current0[j];
            } else {
                // For other steps, current is the next of the previous step
                step[i].current[j] <== step[i-1].next[j];
            }
            step[i].base[j] <== base[j];
            step[i].modulus[j] <== modulus[j];
        }

        // Assign the current exponent bit
        step[i].bit <== exp[BITS - i - 1];
    }

    // Final output is assigned from the next of the last step
    for (var j = 0; j < CHUNK_NUMBER; j++) {
        out[j] <== step[BITS - 1].next[j];
    }
}