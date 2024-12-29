const chai = require("chai");
const path = require("path");
const wasm_tester = require("circom_tester").wasm;

const { poseidon2_hash } = require("../src/utils");

describe("Poseidon2 Circuit test", function () {
    let circuit;

    this.timeout(1000000);

    before(async () => {
        circuit = await wasm_tester(path.join(__dirname, "circuits", "poseidon2_3_test.circom"));
    });

    it("Should check constrain of hash([1, 1, 1]) t=3", async () => {
        const input = [2, 2, 2];
        const res2 = await poseidon2_hash(input);

        const w = await circuit.calculateWitness({ inputs: input });

        await circuit.assertOut(w, { out: res2 });
        await circuit.checkConstraints(w);
    });

});