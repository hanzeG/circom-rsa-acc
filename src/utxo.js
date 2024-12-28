const { prime } = require('bigint-crypto-utils');
const { bigint_to_array, poseidon_hash } = require("./utils");

// UTXO class for const exp = 65537
class UTXO {
    constructor(rsa_65537, secret) {
        this.secret = secret;
        this.rsa = rsa_65537;
        this.commitment = this.rsa.encrypt(secret);
    }

    // Static method to mint a UTXO with a secret (plaintext message)
    // output the ciphertext commitment
    static async mint(rsa_65537) {
        const secret = await prime(rsa_65537.bitLength); // Generate a random prime as plaintext
        return new UTXO(rsa_65537, secret);
    }

    async getNullifierHash(chunk_size, chunk_num) {
        // Calculate nullifier hash using Poseidon hash
        const inv_array = bigint_to_array(chunk_size, chunk_num, this.rsa.inv);
        const secret_array = bigint_to_array(chunk_size, chunk_num, this.secret);
        const nullifier = [inv_array[0], secret_array[0]];
        const nullifierHash = await poseidon_hash(nullifier);
        // console.log("Nullifier Hash:", nullifierHash);
        return nullifierHash;
    }

    async getSecretHash(chunk_size, chunk_num) {
        const secret_array = bigint_to_array(chunk_size, chunk_num, this.secret);
        const secret_hash = await poseidon_hash(secret_array[0], secret_array[1]);
        return secret_hash;
    }
}

module.exports = {
    UTXO
}
