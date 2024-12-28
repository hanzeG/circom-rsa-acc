const path = require("path");
const fs = require("fs");
const { expect } = require("chai");
const { randBetween, min, prime, modInv, modPow, isProbablyPrime } = require('bigint-crypto-utils');
const circom_tester = require("circom_tester");
const wasm_tester = circom_tester.wasm;
const buildPoseidon = require("circomlibjs").buildPoseidonOpt;
const { utils } = require('ffjavascript');
const buildMimcSponge = require("circomlibjs").buildMimcSponge;

const { USER } = require("../src/user");
const { RSA_65537 } = require("../src/rsa_65537");
const { bigint_to_array, generateRabinMillerInput } = require("../src/utils");

const chunk_size = 64;
const chunk_num = 16;
const secret_bit = 512;
const exp = 65537n;

describe("Test pow_mod_1024.circom: pow_mod for random 1024-bit N with constant exp 65537", function () {
    this.timeout(1000 * 1000);

    let circuit;
    let rsa_65537;

    before(async function () {
        circuit = await wasm_tester(path.join(__dirname, "circuits", "pow_mod_1024_const_65537.circom"));
        // Initialize RSA accumulator with specified bit lengths (N = 1024 bits)
        rsa_65537 = await RSA_65537.initialize(secret_bit);
    });

    it("should calculate (g^65537) % N correctly", async function () {
        const plaintext = await prime(secret_bit);
        const ciphertext = rsa_65537.encrypt(plaintext);

        const plaintext_array = bigint_to_array(chunk_size, chunk_num, plaintext);
        const n_array = bigint_to_array(chunk_size, chunk_num, rsa_65537.N);
        const ciphertext_array = bigint_to_array(chunk_size, chunk_num, ciphertext);

        const input = {
            base: plaintext_array,
            exp: exp,
            modulus: n_array
        };

        // Save the input object to a JSON file at relative path "../circuit_input"
        const outputPath = path.join(__dirname, "../circuit_input/pow_mod_1024_const_65537.json");
        fs.writeFileSync(outputPath, JSON.stringify(input, null, 2));

        const witness = await circuit.calculateWitness(input);

        for (let i = 0; i < 16; i++) {
            expect(witness[i + 1]).to.equal(ciphertext_array[i]);
        }
        await circuit.checkConstraints(witness);
    });
});

describe("Test spend.circom: Alice spends a UTXO (minted by Bob) and generates a nullifier hash", function () {
    this.timeout(1000 * 1000);

    let circuit;
    let user;

    before(async function () {
        circuit = await wasm_tester(path.join(__dirname, "circuits", "spend.circom"));
        // Initialize RSA accumulator with specified bit lengths (N = 1024 bits)
        // x should be less than F
        user = await bsrpuser.initialize(1024, 1024, 1024, 128);
    });

    it("should verify witness and generate nullifier hash correctly", async function () {
        // Bob generates a new x (to be spent next) for Alice
        const x = await prime(128);
        // Bob accumulates x into the accumulator and generates a commitment secretly
        const commitment = modPow(user.A, x, user.N);

        // Alice generates a proof (witness) that she can spend the commitment
        const proof = modPow(commitment, modInv(user.secret, user.phiN), user.N);
        // Verify the proof in plain (non-circuit)
        const verification = modPow(proof, user.secret, user.N) === commitment;
        console.log("Verification result:", verification);

        // Simulate an incremental Merkle tree
        const depth = 20;
        const zeroValue = 513;
        const mimcSponge = await buildMimcSponge();
        const F1 = mimcSponge.F;
        // Initialize an incremental Merkle tree with depth and initial value
        let elementPath = new Array(depth).fill(0);
        let indexPath = new Array(depth).fill(0);
        let tmp = zeroValue;
        for (let i = 0; i < depth; i++) {
            elementPath[i] = tmp;
            tmp = F1.toObject(mimcSponge.multiHash([tmp, tmp], 0, 1));
            i++;
        }

        const N_array = bigint_to_array(64, 32, user.N);
        const witness_array = bigint_to_array(64, 32, proof);
        const commitment_array = bigint_to_array(64, 32, commitment);

        // Update the Merkle tree with Bob's new commitment and get the new root hash
        tmp = F1.toObject(mimcSponge.multiHash([commitment_array[0], commitment_array[1]], 0, 1));
        for (let i = 0; i < indexPath.length; i++) {
            if (indexPath[i] === 0) {
                tmp = F1.toObject(mimcSponge.multiHash([tmp, elementPath[i]], 0, 1));
            } else {
                tmp = F1.toObject(mimcSponge.multiHash([elementPath[i], tmp], 0, 1));
            }
        }
        let root = tmp;

        // Calculate nullifier hash using Poseidon hash
        const poseidonHash = await buildPoseidon(); // Initialize Poseidon hash function
        const F2 = poseidonHash.F; // Finite field used by Poseidon
        const nullifier = [witness_array[0], witness_array[1]];
        const nullifierHash = F2.toObject(poseidonHash(nullifier));
        console.log("Nullifier Hash:", nullifierHash);

        const input = {
            N: N_array,
            witness: witness_array,
            secret: user.secret,
            commitment: commitment_array,
            nullifierHash: nullifierHash,

            root: root,
            pathElements: elementPath,
            pathIndices: indexPath,

            receipt: 0,
            relayer: 0,
            fee: 0,
            refund: 0
        };

        // Save the input object to a JSON file at relative path "../circuit_input"
        const outputPath = path.join(__dirname, "../circuit_input/spend.json");
        fs.writeFileSync(outputPath, JSON.stringify(input, null, 2));

        const witness = await circuit.calculateWitness(input);

        expect(witness[1]).to.equal(1n);
        await circuit.checkConstraints(witness);
    });
});