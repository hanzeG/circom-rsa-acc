const { bigint_to_array, poseidon_hash } = require("./utils");
const { RSA_65537 } = require("./rsa_65537");
const { UTXO } = require("./utxo");

// USER class for const exp = 65537
class USER {
    constructor(rsa_65537) {
        this.rsa = rsa_65537;
    }

    // Static method to register a user account with a the security length
    static async register(bitLength) {
        const rsa_65537 = await RSA_65537.initialize(bitLength); // Generate a random prime as plaintext
        return new USER(rsa_65537);
    }

    // Calculate the consistency of secret hash using Poseidon hash
    async check_UTXO(utxo, chunk_size, chunk_num) {
        const m = this.rsa.decrypt(utxo.commitment);
        const m_array = bigint_to_array(chunk_size, chunk_num, m);
        const m_hash = await poseidon_hash(m_array[0], m_array[1]);
        const expected_m_hash = await utxo.getSecretHash(chunk_size, chunk_num);

        return m_hash === expected_m_hash;
    }

    async mint_UTXO(user) {
        return await UTXO.mint(user.rsa);
    }
}

module.exports = {
    USER
}
