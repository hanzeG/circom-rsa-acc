const path = require("path");
const fs = require("fs");
const { expect } = require("chai");
const circom_tester = require("circom_tester");
const wasm_tester = circom_tester.wasm;

const { USER } = require("../src/user");
const { MT } = require("../src/mt");
const { bigint_to_array } = require("../src/utils");

const chunk_size = 64;
const chunk_num = 32;
const security_bit = 1024;

const mt_zero = 513;
const mt_depth = 20;

describe("Test register_2048.circom: register with secret prime p, q to generate N", function () {
    this.timeout(1000 * 1000);

    let circuit;
    let user;

    before(async function () {
        circuit = await wasm_tester(path.join(__dirname, "circuits", "register_2048.circom"));
        user = await USER.register(security_bit, chunk_size, chunk_num);
    });

    it("should register successfully", async function () {
        const p_array = bigint_to_array(chunk_size, chunk_num, user.rsa.p);
        const q_array = bigint_to_array(chunk_size, chunk_num, user.rsa.q);
        const n_array = bigint_to_array(chunk_size, chunk_num, user.rsa.N);

        const input = {
            p: p_array,
            q: q_array
        };

        // Save the input object to a JSON file at relative path "../circuit_input"
        const outputPath = path.join(__dirname, "../circuit_input/register_2048.json");
        fs.writeFileSync(outputPath, JSON.stringify(input, null, 2));

        const witness = await circuit.calculateWitness(input);

        for (let i = 0; i < chunk_num; i++) {
            expect(witness[i + 1]).to.equal(n_array[i]);
        }
        await circuit.checkConstraints(witness);
    });
});

describe("Test ex_transfer_2048.circom: Alice external transfer UTXO to Bob", function () {
    this.timeout(1000 * 1000);

    let circuit;
    let mt;
    let alice;
    let bob;

    before(async function () {
        circuit = await wasm_tester(path.join(__dirname, "circuits", "ex_transfer_2048.circom"));
        mt = await MT.build(mt_zero, mt_depth);
        alice = await USER.register(security_bit, chunk_size, chunk_num);
        bob = await USER.register(security_bit, chunk_size, chunk_num);
    });

    it("should external transfer successfully", async function () {
        // alice mint UTXO for bob
        const ex_utxo = await alice.mint_UTXO(bob, mt);

        const target_N_array = bigint_to_array(chunk_size, chunk_num, ex_utxo.rsa.N);
        const secret_array = bigint_to_array(chunk_size, chunk_num, ex_utxo.secret);
        const ciphertext_array = bigint_to_array(chunk_size, chunk_num, ex_utxo.ciphertext);

        const input = {
            target_N: target_N_array,
            secret: secret_array,
            exp: ex_utxo.rsa.exp
        };

        // Save the input object to a JSON file at relative path "../circuit_input"
        const outputPath = path.join(__dirname, "../circuit_input/ex_transfer_2048.json");
        fs.writeFileSync(outputPath, JSON.stringify(input, null, 2));

        const witness = await circuit.calculateWitness(input);

        // check the ciphertext
        for (let i = 0; i < chunk_num; i++) {
            expect(witness[i + 1]).to.equal(ciphertext_array[i]);
        }

        // check the commitment consistency (secret/ message hash)
        expect(witness[chunk_num + 1]).to.equal(ex_utxo.commitment);

        await circuit.checkConstraints(witness);
    });
});

describe("Test spend_2048.circom: Bob spend UTXO from Alice", function () {
    this.timeout(1000 * 1000);

    let circuit;
    let mt;
    let alice;
    let bob;

    before(async function () {
        circuit = await wasm_tester(path.join(__dirname, "circuits", "spend_2048.circom"));
        mt = await MT.build(mt_zero, mt_depth);
        alice = await USER.register(security_bit, chunk_size, chunk_num);
        bob = await USER.register(security_bit, chunk_size, chunk_num);
    });

    it("should spend UTXO successfully", async function () {
        // alice mint UTXO for bob
        const ex_utxo = await alice.mint_UTXO(bob, mt);

        const message_array = bigint_to_array(chunk_size, chunk_num, ex_utxo.secret);
        const messageHash = ex_utxo.commitment;
        // console.log(messageHash);
        const inv_array = bigint_to_array(chunk_size, chunk_num, bob.rsa.inv);

        // bob spend the UTXO and get the nullifier hash
        const nullifierHash = await bob.spend_UTXO(ex_utxo, mt);
        // console.log(nullifierHash);

        const input = {
            message: message_array,
            messageHash: messageHash,
            inv: inv_array,
            nullifierHash: nullifierHash,
            root: ex_utxo.root,
            pathElements: ex_utxo.merkle_proof[0],
            pathIndices: ex_utxo.merkle_proof[1],

            receipt: 0,
            relayer: 0,
            fee: 0,
            refund: 0
        };

        // console.log(input);

        // Save the input object to a JSON file at relative path "../circuit_input"
        const outputPath = path.join(__dirname, "../circuit_input/spend_2048.json");
        fs.writeFileSync(outputPath, JSON.stringify(input, null, 2));

        const witness = await circuit.calculateWitness(input);

        expect(witness[1]).to.equal(1n);
        await circuit.checkConstraints(witness);
    });
});

describe("Test in_transfer_2048.circom: Bob internal transfer to Charles", function () {
    this.timeout(1000 * 1000);

    let circuit;
    let mt;
    let alice;
    let bob;
    let charles;

    before(async function () {
        circuit = await wasm_tester(path.join(__dirname, "circuits", "in_transfer_2048.circom"));
        mt = await MT.build(mt_zero, mt_depth);
        alice = await USER.register(security_bit, chunk_size, chunk_num);
        bob = await USER.register(security_bit, chunk_size, chunk_num);
        charles = await USER.register(security_bit, chunk_size, chunk_num);
    });

    it("should internal transfer UTXO successfully", async function () {
        // step.1 alice external transfer UTXO for bob
        const ex_utxo = await alice.mint_UTXO(bob, mt);

        // step.2 bob spending the UTXO and get the nullifier hash (not spend in fact)
        const nullifierHash = await bob.spend_UTXO(ex_utxo, mt);

        // step.3 bob mint a new UTXO' with UTXO for charles
        const in_utxo = await bob.mint_UTXO(charles, mt);

        const input = {
            mint_message: bigint_to_array(chunk_size, chunk_num, in_utxo.secret),
            mint_N: bigint_to_array(chunk_size, chunk_num, in_utxo.rsa.N),
            mint_exp: in_utxo.rsa.exp,

            spend_message: bigint_to_array(chunk_size, chunk_num, ex_utxo.secret),
            spend_messageHash: ex_utxo.commitment,
            spend_inv: bigint_to_array(chunk_size, chunk_num, ex_utxo.rsa.inv),
            spend_nullifierHash: nullifierHash,

            root: ex_utxo.root,
            pathElements: ex_utxo.merkle_proof[0],
            pathIndices: ex_utxo.merkle_proof[1],

            receipt: 0,
            relayer: 0,
            fee: 0,
            refund: 0
        };

        // console.log(input);

        // Save the input object to a JSON file at relative path "../circuit_input"
        const outputPath = path.join(__dirname, "../circuit_input/in_transfer_2048.json");
        fs.writeFileSync(outputPath, JSON.stringify(input, null, 2));

        const witness = await circuit.calculateWitness(input);

        const ciphertext_array = bigint_to_array(chunk_size, chunk_num, in_utxo.ciphertext);

        // check the ciphertext
        for (let i = 0; i < chunk_num; i++) {
            expect(witness[i + 1]).to.equal(ciphertext_array[i]);
        }

        // check the commitment consistency (secret/ message hash)
        expect(witness[chunk_num + 1]).to.equal(in_utxo.commitment);

        await circuit.checkConstraints(witness);
    });
});