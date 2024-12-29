const { prime } = require('bigint-crypto-utils');
const { bigint_to_array, poseidon2_hash } = require("./utils");
// UTXO class for const exp = 65537
class UTXO {
    constructor(rsa_65537, secret, root, merkle_proof, chunk_size, chunk_num, secret_hash) {
        this.secret = secret;
        this.rsa = rsa_65537;
        this.merkle_proof = merkle_proof;
        this.root = root;
        this.chunk_size = chunk_size;
        this.chunk_num = chunk_num;
        this.commitment = secret_hash;
        this.ciphertext = this.rsa.encrypt(secret);
    }

    // Static method to mint a UTXO with a secret (plaintext message)
    // output the ciphertext commitment
    static async mint(rsa_65537, mt, chunk_size, chunk_num) {
        const secret = await prime(rsa_65537.bitLength); // Generate a random prime as plaintext
        const secret_array = bigint_to_array(chunk_size, chunk_num, secret);
        const secret_hash = await poseidon2_hash([secret_array[0], 1, 1]);
        const commitment = secret_hash[0];
        const [root, merkle_proof] = await mt.insert(commitment);

        return new UTXO(rsa_65537, secret, root, merkle_proof, chunk_size, chunk_num, commitment);
    }

    async getNullifierHash() {
        // Calculate nullifier hash using Poseidon hash
        const inv_array = bigint_to_array(this.chunk_size, this.chunk_num, this.rsa.inv);
        const secret_array = bigint_to_array(this.chunk_size, this.chunk_num, this.secret);
        const nullifier = [inv_array[0], secret_array[0], 1];
        const nullifierHash = await poseidon2_hash(nullifier);
        // console.log("Nullifier Hash:", nullifierHash);
        return nullifierHash[0];
    }

    // async getSecretHash() {
    //     const secret_array = bigint_to_array(this.chunk_size, this.chunk_num, this.secret);
    //     const secret_hash = await poseidon2_hash(secret_array[0], 1, 1);
    //     return secret_hash[0];
    // }
}

module.exports = {
    UTXO
}
