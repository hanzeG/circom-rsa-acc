const path = require("path");
const fs = require("fs");
const { expect } = require("chai");
const { randBetween, min, prime, modInv, modPow, isProbablyPrime } = require('bigint-crypto-utils');
const circom_tester = require("circom_tester");
const wasm_tester = circom_tester.wasm;
const { generateRabinMillerInput } = require("../src/utils");

describe("Test primality.circom: verify primality of 64-bit bigint", function () {
    this.timeout(1000 * 1000);

    let circuit;

    before(async function () {
        circuit = await wasm_tester(path.join(__dirname, "circuits", "primality_64.circom"));
    });

    it("should x is a 64-bit prime", async function () {
        // Generate a new x to update A (64-bit random prime) 
        // x should be less than F
        const x = await prime(64);
        console.log(x);

        // Primality check in plain (non-circuit)
        const prime_verification = await isProbablyPrime(x);
        console.log("Primality check in plain:", prime_verification);

        // Base number for Rabin-Miller test
        const baseNumber = 5;

        // Generate input for the circuit
        const inputParams = generateRabinMillerInput(x, baseNumber);
        console.log(inputParams);

        const input = {
            n: inputParams.n,
            a: inputParams.a,
            d: inputParams.d,
            r: inputParams.r
        };

        // Save the input object to a JSON file at relative path "../circuit_input"
        const outputPath = path.join(__dirname, "../circuit_input/primality_64.json");
        fs.writeFileSync(outputPath, JSON.stringify(input, null, 2));

        const witness = await circuit.calculateWitness(input);

        expect(witness[1]).to.equal(1n);

        // TODO: Check the signal output `isPrime`
        await circuit.checkConstraints(witness);
    });

    it("should x is not a 64-bit prime", async function () {
        // Generate a new x to update A (64-bit random prime) 
        // x should be less than F
        const x = await prime(64) - 1n;
        console.log(x);

        // Primality check in plain (non-circuit)
        const prime_verification = await isProbablyPrime(x);
        console.log("Primality check in plain:", prime_verification);

        // Base number for Rabin-Miller test
        const baseNumber = 5;

        // Generate input for the circuit
        const inputParams = generateRabinMillerInput(x, baseNumber);
        console.log(inputParams);

        const input = {
            n: inputParams.n,
            a: inputParams.a,
            d: inputParams.d,
            r: inputParams.r
        };

        // Save the input object to a JSON file at relative path "../circuit_input"
        const outputPath = path.join(__dirname, "../circuit_input/primality_64.json");
        fs.writeFileSync(outputPath, JSON.stringify(input, null, 2));

        const witness = await circuit.calculateWitness(input);

        expect(witness[1]).to.equal(0n);

        await circuit.checkConstraints(witness);
    });
});

describe("Test primality_128.circom: verify primality of 128-bit bigint", function () {
    this.timeout(1000 * 1000);

    let circuit;

    before(async function () {
        circuit = await wasm_tester(path.join(__dirname, "circuits", "primality_128.circom"));
    });

    it("should x is a 127-bit prime", async function () {
        // Generate a new x to update A (128-bit random prime) 
        // x should be less than F
        const x = await prime(127);
        console.log(x);

        // Primality check in plain (non-circuit)
        const prime_verification = await isProbablyPrime(x);
        console.log("Primality check in plain:", prime_verification);

        // Base number for Rabin-Miller test
        const baseNumber = 5;

        // Generate input for the circuit
        const inputParams = generateRabinMillerInput(x, baseNumber);
        console.log(inputParams);

        const input = {
            n: inputParams.n,
            a: inputParams.a,
            d: inputParams.d,
            r: inputParams.r
        };

        // Save the input object to a JSON file at relative path "../circuit_input"
        const outputPath = path.join(__dirname, "../circuit_input/primality_128.json");
        fs.writeFileSync(outputPath, JSON.stringify(input, null, 2));

        const witness = await circuit.calculateWitness(input);

        expect(witness[1]).to.equal(1n);

        // TODO: Check the signal output `isPrime`
        await circuit.checkConstraints(witness);
    });

    it("should x is not a 127-bit prime", async function () {
        // Generate a new x to update A (127-bit random prime) 
        // x should be less than F
        const x = await prime(127) - 1n;
        console.log(x);

        // Primality check in plain (non-circuit)
        const prime_verification = await isProbablyPrime(x);
        console.log("Primality check in plain:", prime_verification);

        // Base number for Rabin-Miller test
        const baseNumber = 5;

        // Generate input for the circuit
        const inputParams = generateRabinMillerInput(x, baseNumber);
        console.log(inputParams);

        const input = {
            n: inputParams.n,
            a: inputParams.a,
            d: inputParams.d,
            r: inputParams.r
        };

        // Save the input object to a JSON file at relative path "../circuit_input"
        const outputPath = path.join(__dirname, "../circuit_input/primality_128.json");
        fs.writeFileSync(outputPath, JSON.stringify(input, null, 2));

        const witness = await circuit.calculateWitness(input);

        expect(witness[1]).to.equal(0n);

        await circuit.checkConstraints(witness);
    });
});
