const { bigint_to_array, poseidon2_hash } = require("./utils");
const { RSA_65537 } = require("./rsa_65537");
const { UTXO } = require("./utxo");

// USER class for const exp = 65537
class USER {
    constructor(rsa_65537, chunk_size, chunk_num) {
        this.rsa = rsa_65537;
        this.chunk_size = chunk_size;
        this.chunk_num = chunk_num;
    }

    // Static method to register a user account with a the security length
    static async register(bitLength, chunk_size, chunk_num) {
        const rsa_65537 = await RSA_65537.initialize(bitLength); // Generate a random prime as plaintext
        return new USER(rsa_65537, chunk_size, chunk_num);
    }

    // Calculate the consistency of secret hash using Poseidon hash
    async check_UTXO(utxo, mt) {
        const m = this.rsa.decrypt(utxo.commitment);
        const m_array = bigint_to_array(this.chunk_size, this.chunk_num, m);
        const m_hash = await poseidon2_hash(m_array[0], 1, 1);
        const expected_m_hash = await utxo.getSecretHash(this.chunk_size, this.chunk_num);

        if (mt.check_membership(utxo.commitment, utxo.root, utxo.merkle_proof)) {
            return m_hash === expected_m_hash;
        } else {
            console.log("does not exist in MT!");
            return false;
        }
    }

    async mint_UTXO(user, mt) {
        return await UTXO.mint(user.rsa, mt, user.chunk_size, user.chunk_num);
    }

    async spend_UTXO(utxo, mt) {
        try {
            const canSpend = this.check_UTXO(utxo, mt);
            if (canSpend) {
                // If the UTXO is valid, attempt to get the Nullifier Hash
                return await utxo.getNullifierHash();
            } else {
                // If the UTXO cannot be spent, return 0
                return 0;
            }
        } catch (error) {
            // Handle any potential errors during execution
            console.error("Error in spend_UTXO:", error);
            throw error; // Or return a default value, e.g., `0`
        }
    }
    async get_random_message() {
        return await prime(2 * this.rsa.bitLength);
    }
}

module.exports = {
    USER
}
