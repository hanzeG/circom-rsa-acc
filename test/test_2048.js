const path = require("path");
const fs = require("fs");
const { expect } = require("chai");
const { randBetween, min, prime, modInv, modPow, isProbablyPrime } = require('bigint-crypto-utils');
const circom_tester = require("circom_tester");
const wasm_tester = circom_tester.wasm;
const buildPoseidon = require("circomlibjs").buildPoseidonOpt;
const { utils } = require('ffjavascript');
const buildMimcSponge = require("circomlibjs").buildMimcSponge;

// const F1Field = require("ffjavascript").F1Field;
// const Scalar = require("ffjavascript").Scalar;
// const p = Scalar.fromString("21888242871839275222246405745257275088548364400416034343698204186575808495617");
// const Fr = new F1Field(p);

// RSA Accumulator class
class bsrpRAcc {
    constructor(g, p, q, secret) {
        this.g = g; // Base value
        this.p = p; // First prime
        this.q = q; // Second prime
        this.secret = secret; // Secret exponent
        this.N = p * q; // Modulus
        this.phiN = (p - 1n) * (q - 1n); // Euler's totient function
        this.A = modPow(this.g, secret, this.N); // Initial accumulator A = g^secret mod N
        // console.debug(`Initialized accumulator: g=${this.g}, p=${this.p}, q=${this.q}, secret=${this.secret}, N=${this.N}`);
    }

    // Accumulate a new value x into the accumulator
    accumulate(x) {
        // console.debug(`Accumulating value: x=${x}`);
        this.A = modPow(this.A, x, this.N);
        // console.debug(`Updated accumulator value: A=${this.A}`);
    }

    // Generate a proof that x is part of the current accumulator
    generateProof(x) {
        // console.debug(`Generating proof for x=${x}`);
        const y = modInv(x, this.phiN); // Calculate the modular inverse of x
        // console.debug(`yyy: yyy=${y}`);
        const proof = modPow(this.A, y, this.N);
        // console.debug(`Generated proof: proof=${proof}`);
        return proof;
    }

    // Verify the proof that x is part of the current accumulator
    verifyProof(x, proof) {
        // console.debug(`Verifying proof: x=${x}, proof=${proof}`);
        const AVerify = modPow(proof, x, this.N); // Recompute A from the proof
        const result = AVerify === this.A;
        // console.debug(`Verification result: AVerify=${AVerify}, A=${this.A}, result=${result}`);
        return result;
    }

    // Static method to initialize the accumulator with random parameters
    static async initialize(bitLengthG, bitLengthP, bitLengthQ, bitLengthX) {
        // console.debug(`Initializing bsrpRAcc with bit lengths: g=${bitLengthG}, p=${bitLengthP}, q=${bitLengthQ}, secret=${bitLengthX}`);
        const g = await prime(bitLengthG); // Generate a random prime for g
        const p = await prime(bitLengthP); // Generate a random prime for p
        const q = await prime(bitLengthQ); // Generate a random prime for q
        const secret = await prime(bitLengthX); // Generate a random prime for secret
        // console.debug(`Generated parameters: g=${g}, p=${p}, q=${q}, secret=${secret}`);
        return new bsrpRAcc(g, p, q, secret);
    }
}

function bigint_to_array(n, k, x) {
    let mod = 1n;
    for (let idx = 0; idx < n; idx++) {
        mod = mod * 2n;
    }

    let ret = [];
    let x_temp = x;
    for (let idx = 0; idx < k; idx++) {
        ret.push(x_temp % mod);
        x_temp = x_temp / mod;
    }
    return ret;
}

/**
 * Generate input parameters for Rabin-Miller primality test signals
 * @param {string|number} n - The integer to be checked for primality
 * @param {number} [k] - Number of bases `a`
 * @returns {Object} Object containing `n`, `a`, `d`, and `r`
 */
function generateRabinMillerInput(N, k) {
    if (N < 2n) {
        throw new Error("n must be greater than or equal to 2");
    }

    // Calculate d and r such that n - 1 = d * 2^r, where d is odd
    let d = N - 1n;
    let r = 0;
    while (d % 2n === 0n) {
        d /= 2n;
        r += 1;
    }

    // Generate k random bases a[i] where 2 <= a[i] <= n - 2
    const a = [];
    for (let i = 0; i < k; i++) {
        if (N <= 4n) {
            // When n <= 4, a must be 2
            a.push(2n);
        } else {
            a.push(randBetween(N - 2n, 2n));
        }
    }

    return {
        n: N,
        a: a,
        d: d,
        r: BigInt(r)
    };
}

// describe("Test primality.circom: verify primality of 128-bit x", function () {
//     this.timeout(1000 * 1000);

//     let circuit;

//     before(async function () {
//         circuit = await wasm_tester(path.join(__dirname, "circuits", "primality.circom"));
//     });

//     it("should x is a 128-bit prime", async function () {
//         // Generate a new x to update A (128-bit random prime) 
//         // x should be less than F
//         const x = await prime(128);
//         // console.log(x);

//         // Primality check in plain (non-circuit)
//         const prime_verification = await isProbablyPrime(x);
//         console.log("Primality check in plain:", prime_verification);

//         // Base number for Rabin-Miller test
//         const baseNumber = 5;

//         // Generate input for the circuit
//         const inputParams = generateRabinMillerInput(x, baseNumber);
//         // console.log(inputParams);

//         const input = {
//             n: inputParams.n,
//             a: inputParams.a,
//             d: inputParams.d,
//             r: inputParams.r
//         };

//         // Save the input object to a JSON file at relative path "../circuit_input"
//         const outputPath = path.join(__dirname, "../circuit_input/primality.json");
//         fs.writeFileSync(outputPath, JSON.stringify(input, null, 2));

//         const witness = await circuit.calculateWitness(input);

//         // console.log(witness);
//         // expect(witness[1]).to.equal(1n);

//         // TODO: Check the signal output `isPrime`
//         await circuit.checkConstraints(witness);
//     });
// });

describe("Test pow_mod_128.circom: pow_mod for random 2048-bit N, 128-bit x", function () {
    this.timeout(1000 * 1000);

    let circuit;
    let racc;

    before(async function () {
        circuit = await wasm_tester(path.join(__dirname, "circuits", "pow_mod_2048_128.circom"));
        // Initialize RSA accumulator with specified bit lengths (N = 2048 bits)
        // x should be less than F
        racc = await bsrpRAcc.initialize(2048, 1024, 1024, 128);
    });

    it("should calculate (g^x) % N correctly", async function () {
        const g_array = bigint_to_array(64, 32, racc.g);
        const n_array = bigint_to_array(64, 32, racc.N);
        const result_array = bigint_to_array(64, 32, racc.A);

        const input = {
            base: g_array,
            exp: racc.secret,
            modulus: n_array
        };

        // Save the input object to a JSON file at relative path "../circuit_input"
        const outputPath = path.join(__dirname, "../circuit_input/pow_mod_2048_128.json");
        fs.writeFileSync(outputPath, JSON.stringify(input, null, 2));

        const witness = await circuit.calculateWitness(input);

        for (let i = 0; i < 32; i++) {
            expect(witness[i + 1]).to.equal(result_array[i]);
        }
        await circuit.checkConstraints(witness);
    });
});

// describe("Test pow_mod_64.circom: pow_mod for random 2048-bit N, 64-bit x", function () {
//     this.timeout(1000 * 1000);

//     let circuit;
//     let racc;

//     before(async function () {
//         circuit = await wasm_tester(path.join(__dirname, "circuits", "pow_mod_64.circom"));
//         // Initialize RSA accumulator with specified bit lengths (N = 2048 bits)
//         // x should be less than F
//         racc = await bsrpRAcc.initialize(2048, 1024, 1024, 64);
//     });

//     it("should calculate (g^x) % N correctly", async function () {
//         const g_array = bigint_to_array(64, 32, racc.g);
//         const n_array = bigint_to_array(64, 32, racc.N);
//         const result_array = bigint_to_array(64, 32, racc.A);

//         const input = {
//             base: g_array,
//             exp: racc.secret,
//             modulus: n_array
//         };

//         // Save the input object to a JSON file at relative path "../circuit_input"
//         const outputPath = path.join(__dirname, "../circuit_input/pow_mod_64.json");
//         fs.writeFileSync(outputPath, JSON.stringify(input, null, 2));

//         const witness = await circuit.calculateWitness(input);

//         for (let i = 0; i < 32; i++) {
//             expect(witness[i + 1]).to.equal(result_array[i]);
//         }
//         await circuit.checkConstraints(witness);
//     });
// });

// describe("Test verify_wtns.circom: verify witness for membership of 128-bit x for 2048-bit N", function () {
//     this.timeout(1000 * 1000);

//     let circuit;
//     let racc;
//     let x;

//     before(async function () {
//         circuit = await wasm_tester(path.join(__dirname, "circuits", "verify_wtns.circom"));
//         // Initialize RSA accumulator with specified bit lengths (N = 2048 bits)
//         // x should be less than F
//         racc = await bsrpRAcc.initialize(2048, 1024, 1024, 128);
//         // Generate a new x to update A (128-bit random prime)
//         x = await prime(128);
//     });

//     it("should calculate A' == (w^x) % N correctly", async function () {
//         // Accumulate x into the accumulator
//         racc.accumulate(x);

//         // Alice generates a proof (witness) that `secret` is part of the latest accumulator
//         const proof = racc.generateProof(racc.secret);

//         // Verify the proof in plain (non-circuit)
//         const verification = racc.verifyProof(racc.secret, proof);
//         console.log("Verification result:", verification);

//         const n_array = bigint_to_array(64, 32, racc.N);
//         const w_array = bigint_to_array(64, 32, proof);
//         const target_array = bigint_to_array(64, 32, racc.A);

//         const input = {
//             modulus: n_array,
//             witness: w_array,
//             secret: racc.secret,
//             target: target_array
//         };

//         // Save the input object to a JSON file at relative path "../circuit_input"
//         const outputPath = path.join(__dirname, "../circuit_input/verify_wtns.json");
//         fs.writeFileSync(outputPath, JSON.stringify(input, null, 2));

//         const witness = await circuit.calculateWitness(input);

//         // Number of chunks = 32
//         expect(witness[1]).to.equal(32n);

//         await circuit.checkConstraints(witness);
//     });
// });

// describe("Test spend.circom: Alice spends a UTXO (minted by Bob) and generates a nullifier hash", function () {
//     this.timeout(1000 * 1000);

//     let circuit;
//     let racc;

//     before(async function () {
//         circuit = await wasm_tester(path.join(__dirname, "circuits", "spend.circom"));
//         // Initialize RSA accumulator with specified bit lengths (N = 2048 bits)
//         // x should be less than F
//         racc = await bsrpRAcc.initialize(2048, 1024, 1024, 128);
//     });

//     it("should verify witness and generate nullifier hash correctly", async function () {
//         // Bob generates a new x (to be spent next) for Alice
//         const x = await prime(128);
//         // Bob accumulates x into the accumulator and generates a commitment secretly
//         const commitment = modPow(racc.A, x, racc.N);

//         // Alice generates a proof (witness) that she can spend the commitment
//         const proof = modPow(commitment, modInv(racc.secret, racc.phiN), racc.N);
//         // Verify the proof in plain (non-circuit)
//         const verification = modPow(proof, racc.secret, racc.N) === commitment;
//         console.log("Verification result:", verification);

//         // Simulate an incremental Merkle tree
//         const depth = 20;
//         const zeroValue = 513;
//         const mimcSponge = await buildMimcSponge();
//         const F1 = mimcSponge.F;
//         // Initialize an incremental Merkle tree with depth and initial value
//         let elementPath = new Array(depth).fill(0);
//         let indexPath = new Array(depth).fill(0);
//         let tmp = zeroValue;
//         for (let i = 0; i < depth; i++) {
//             elementPath[i] = tmp;
//             tmp = F1.toObject(mimcSponge.multiHash([tmp, tmp], 0, 1));
//             i++;
//         }

//         const N_array = bigint_to_array(64, 32, racc.N);
//         const witness_array = bigint_to_array(64, 32, proof);
//         const commitment_array = bigint_to_array(64, 32, commitment);

//         // Update the Merkle tree with Bob's new commitment and get the new root hash
//         tmp = F1.toObject(mimcSponge.multiHash([commitment_array[0], commitment_array[1]], 0, 1));
//         for (let i = 0; i < indexPath.length; i++) {
//             if (indexPath[i] === 0) {
//                 tmp = F1.toObject(mimcSponge.multiHash([tmp, elementPath[i]], 0, 1));
//             } else {
//                 tmp = F1.toObject(mimcSponge.multiHash([elementPath[i], tmp], 0, 1));
//             }
//         }
//         let root = tmp;

//         // Calculate nullifier hash using Poseidon hash
//         const poseidonHash = await buildPoseidon(); // Initialize Poseidon hash function
//         const F2 = poseidonHash.F; // Finite field used by Poseidon
//         const nullifier = [witness_array[0], witness_array[1]];
//         const nullifierHash = F2.toObject(poseidonHash(nullifier));
//         console.log("Nullifier Hash:", nullifierHash);

//         const input = {
//             N: N_array,
//             witness: witness_array,
//             secret: racc.secret,
//             commitment: commitment_array,
//             nullifierHash: nullifierHash,

//             root: root,
//             pathElements: elementPath,
//             pathIndices: indexPath,

//             receipt: 0,
//             relayer: 0,
//             fee: 0,
//             refund: 0
//         };

//         // Save the input object to a JSON file at relative path "../circuit_input"
//         const outputPath = path.join(__dirname, "../circuit_input/spend.json");
//         fs.writeFileSync(outputPath, JSON.stringify(input, null, 2));

//         const witness = await circuit.calculateWitness(input);

//         expect(witness[1]).to.equal(1n);
//         await circuit.checkConstraints(witness);
//     });
// });