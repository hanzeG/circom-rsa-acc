const path = require("path");
const fs = require("fs");
const { expect } = require("chai");
const { prime } = require('bigint-crypto-utils');
const circom_tester = require("circom_tester");
const wasm_tester = circom_tester.wasm;

const { RSA_65537 } = require("../src/rsa_65537");
const { RSA_ARB } = require("../src/rsa_arbitrary");
const { bigint_to_array, bigintToBitsArray } = require("../src/utils");

describe("Test pow_mod_1024_const_65537.circom: pow_mod for random 1024-bit N with constant exp 65537", function () {
    this.timeout(1000 * 1000);

    const chunk_size = 64;
    const chunk_num = 16;
    const secret_bit = 512;
    const exp = 65537n;
    let circuit;
    let rsa_65537;

    before(async function () {
        circuit = await wasm_tester(path.join(__dirname, "circuits", "pow_mod_1024_const_65537.circom"));
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

        for (let i = 0; i < chunk_num; i++) {
            expect(witness[i + 1]).to.equal(ciphertext_array[i]);
        }
        await circuit.checkConstraints(witness);
    });
});


describe("Test pow_mod_2048_const_65537.circom: pow_mod for random 2048-bit N with constant exp 65537", function () {
    this.timeout(1000 * 1000);

    const chunk_size = 64;
    const chunk_num = 32;
    const secret_bit = 1024;
    const exp = 65537n;
    let circuit;
    let rsa_65537;

    before(async function () {
        circuit = await wasm_tester(path.join(__dirname, "circuits", "pow_mod_2048_const_65537.circom"));
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
        const outputPath = path.join(__dirname, "../circuit_input/pow_mod_2048_const_65537.json");
        fs.writeFileSync(outputPath, JSON.stringify(input, null, 2));

        const witness = await circuit.calculateWitness(input);

        for (let i = 0; i < chunk_num; i++) {
            expect(witness[i + 1]).to.equal(ciphertext_array[i]);
        }
        await circuit.checkConstraints(witness);
    });
});


describe("Test pow_mod_1024_64.circom: pow_mod for random 1024-bit N with random 64-bit exp", function () {
    this.timeout(1000 * 1000);

    const chunk_size = 64;
    const chunk_num = 16;
    const secret_bit = 512;
    const exp_bit = 64;
    let circuit;
    let rsa_arb;

    before(async function () {
        circuit = await wasm_tester(path.join(__dirname, "circuits", "pow_mod_1024_64.circom"));
        rsa_arb = await RSA_ARB.initialize(secret_bit, exp_bit);
    });

    it("should calculate (g^exp) % N correctly", async function () {
        const plaintext = await prime(secret_bit);
        const ciphertext = rsa_arb.encrypt(plaintext);

        const plaintext_array = bigint_to_array(chunk_size, chunk_num, plaintext);
        const n_array = bigint_to_array(chunk_size, chunk_num, rsa_arb.N);
        const ciphertext_array = bigint_to_array(chunk_size, chunk_num, ciphertext);

        const input = {
            base: plaintext_array,
            exp: rsa_arb.exp,
            modulus: n_array
        };

        // Save the input object to a JSON file at relative path "../circuit_input"
        const outputPath = path.join(__dirname, "../circuit_input/pow_mod_1024_64.json");
        fs.writeFileSync(outputPath, JSON.stringify(input, null, 2));

        const witness = await circuit.calculateWitness(input);

        for (let i = 0; i < chunk_num; i++) {
            expect(witness[i + 1]).to.equal(ciphertext_array[i]);
        }
        await circuit.checkConstraints(witness);
    });
});


describe("Test pow_mod_2048_64.circom: pow_mod for random 2048-bit N with random 64-bit exp", function () {
    this.timeout(1000 * 1000);

    const chunk_size = 64;
    const chunk_num = 32;
    const secret_bit = 1024;
    const exp_bit = 64;
    let circuit;
    let rsa_arb;

    before(async function () {
        circuit = await wasm_tester(path.join(__dirname, "circuits", "pow_mod_2048_64.circom"));
        rsa_arb = await RSA_ARB.initialize(secret_bit, exp_bit);
    });

    it("should calculate (g^exp) % N correctly", async function () {
        const plaintext = await prime(secret_bit);
        const ciphertext = rsa_arb.encrypt(plaintext);

        const plaintext_array = bigint_to_array(chunk_size, chunk_num, plaintext);
        const n_array = bigint_to_array(chunk_size, chunk_num, rsa_arb.N);
        const ciphertext_array = bigint_to_array(chunk_size, chunk_num, ciphertext);

        const input = {
            base: plaintext_array,
            exp: rsa_arb.exp,
            modulus: n_array
        };

        // Save the input object to a JSON file at relative path "../circuit_input"
        const outputPath = path.join(__dirname, "../circuit_input/pow_mod_2048_64.json");
        fs.writeFileSync(outputPath, JSON.stringify(input, null, 2));

        const witness = await circuit.calculateWitness(input);

        for (let i = 0; i < chunk_num; i++) {
            expect(witness[i + 1]).to.equal(ciphertext_array[i]);
        }
        await circuit.checkConstraints(witness);
    });
});


describe("Test pow_mod_1024_128.circom: pow_mod for random 1024-bit N with random 128-bit exp", function () {
    this.timeout(1000 * 1000);

    const chunk_size = 64;
    const chunk_num = 16;
    const secret_bit = 512;
    const exp_bit = 128;
    let circuit;
    let rsa_arb;

    before(async function () {
        circuit = await wasm_tester(path.join(__dirname, "circuits", "pow_mod_1024_128.circom"));
        rsa_arb = await RSA_ARB.initialize(secret_bit, exp_bit);
    });

    it("should calculate (g^exp) % N correctly", async function () {
        const plaintext = await prime(secret_bit);
        const ciphertext = rsa_arb.encrypt(plaintext);

        const plaintext_array = bigint_to_array(chunk_size, chunk_num, plaintext);
        const n_array = bigint_to_array(chunk_size, chunk_num, rsa_arb.N);
        const ciphertext_array = bigint_to_array(chunk_size, chunk_num, ciphertext);

        const input = {
            base: plaintext_array,
            exp: rsa_arb.exp,
            modulus: n_array
        };

        // Save the input object to a JSON file at relative path "../circuit_input"
        const outputPath = path.join(__dirname, "../circuit_input/pow_mod_1024_128.json");
        fs.writeFileSync(outputPath, JSON.stringify(input, null, 2));

        const witness = await circuit.calculateWitness(input);

        for (let i = 0; i < chunk_num; i++) {
            expect(witness[i + 1]).to.equal(ciphertext_array[i]);
        }
        await circuit.checkConstraints(witness);
    });
});


describe("Test pow_mod_2048_128.circom: pow_mod for random 2048-bit N with random 128-bit exp", function () {
    this.timeout(1000 * 1000);

    const chunk_size = 64;
    const chunk_num = 32;
    const secret_bit = 1024;
    const exp_bit = 128;
    let circuit;
    let rsa_arb;

    before(async function () {
        circuit = await wasm_tester(path.join(__dirname, "circuits", "pow_mod_2048_128.circom"));
        rsa_arb = await RSA_ARB.initialize(secret_bit, exp_bit);
    });

    it("should calculate (g^exp) % N correctly", async function () {
        const plaintext = await prime(secret_bit);
        const ciphertext = rsa_arb.encrypt(plaintext);

        const plaintext_array = bigint_to_array(chunk_size, chunk_num, plaintext);
        const n_array = bigint_to_array(chunk_size, chunk_num, rsa_arb.N);
        const ciphertext_array = bigint_to_array(chunk_size, chunk_num, ciphertext);

        const input = {
            base: plaintext_array,
            exp: rsa_arb.exp,
            modulus: n_array
        };

        // Save the input object to a JSON file at relative path "../circuit_input"
        const outputPath = path.join(__dirname, "../circuit_input/pow_mod_2048_128.json");
        fs.writeFileSync(outputPath, JSON.stringify(input, null, 2));

        const witness = await circuit.calculateWitness(input);

        for (let i = 0; i < chunk_num; i++) {
            expect(witness[i + 1]).to.equal(ciphertext_array[i]);
        }
        await circuit.checkConstraints(witness);
    });
});