pragma circom 2.0.6;

include "../circomlib/circuits/bitify.circom";
include "../circomlib/circuits/comparators.circom";

// Template for Modular Exponentiation using Repeated Squaring
template ModularExponentiation(nBits) {
    signal input base;
    signal input exp;
    signal input mod;
    signal output result;

    component expBits = Num2Bits(nBits);
    expBits.in <== exp;

    signal tmpResults[nBits + 1];
    signal currentBases[nBits + 1];
    signal applyMultiplier[nBits];

    tmpResults[0] <== 1;
    currentBases[0] <== base;

    for (var i = 0; i < nBits; i++) {
        applyMultiplier[i] <-- expBits.out[i] == 1 ? currentBases[i] : 1;
        tmpResults[i + 1] <-- (tmpResults[i] * applyMultiplier[i]) % mod;
        currentBases[i + 1] <-- (currentBases[i] * currentBases[i]) % mod;
    }

    result <== tmpResults[nBits];
}

// Rabin-Miller Primality Test
template RabinMillerPrimalityTest(k, nBits, maxRounds) {
    signal input n; // test big number
    signal input a[k]; // prime number set
    signal input d; // d * 2^r = n - 1 
    signal input r; // d * 2^r = n - 1
    signal output isPrime;

    signal exponentResults[k];
    signal rabinMillerResults[k];

    component modExp[k];
    component powerModExp[k][maxRounds];

    signal baseCheck[k];
    signal roundCheck[k];
    
    signal powerResults[k][maxRounds];
    
    signal conditionSignals[maxRounds];

    // Precompute the condition signals
    for (var j = 0; j < maxRounds; j++) {
        conditionSignals[j] <-- j < r ? 0 : 1;
    }

    for (var i = 0; i < k; i++) {
        modExp[i] = ModularExponentiation(nBits);
        modExp[i].base <== a[i];
        modExp[i].exp <== d;
        modExp[i].mod <== n;

        exponentResults[i] <== modExp[i].result;
        baseCheck[i] <== (exponentResults[i] - 1) * (exponentResults[i] - (n - 1));
        // log("baseCheck[i]", baseCheck[i]);

        var nMinusOneAcc = 1; // Using var accumulator

        powerResults[i][0] <== exponentResults[i];

        for (var j = 1; j < maxRounds; j++) {
            powerModExp[i][j - 1] = ModularExponentiation(nBits);
            powerModExp[i][j - 1].base <== powerResults[i][j - 1];
            powerModExp[i][j - 1].exp <== 2;
            powerModExp[i][j - 1].mod <== n;
            powerResults[i][j] <== powerModExp[i][j - 1].result;

            var auxNMinusOne = conditionSignals[j] + (powerResults[i][j] - (n - 1)) * (powerResults[i][j] - (n - 1));

            nMinusOneAcc = nMinusOneAcc * auxNMinusOne;
        }

        roundCheck[i] <-- nMinusOneAcc;
        // log("roundCheck[i]", roundCheck[i]);
        rabinMillerResults[i] <== baseCheck[i] * roundCheck[i];
        // log("rabinMillerResults[i]",rabinMillerResults[i]);
    }

    var isPrimeCheck = 0;
    for (var i = 0; i < k; i++) {
        isPrimeCheck += rabinMillerResults[i];
    }

    component isZero = IsZero();
    isZero.in <== isPrimeCheck;

    isPrime <== isZero.out;
}
// Instantiate RabinMillerPrimalityTest with 10 bases and 256-bit exponentiation, max 20 rounds
// component main {public [n, a]} = RabinMillerPrimalityTest(5, 128, 10);
