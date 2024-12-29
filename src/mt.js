const { poseidon2_hash } = require("./utils");

// Incremental merkle tree class with Poseidon2 hash
class MT {
    constructor(zero, depth, root, roots, elementPath, indexPath, index) {
        this.zero = zero;
        this.depth = depth;
        this.root = root;
        this.roots = roots;
        this.elementPath = elementPath;
        this.indexPath = indexPath;
        this.index = index;
    }

    // Static method to build an incremental MT
    static async build(zero, depth) {
        let elementPath = new Array(depth).fill(0);
        let indexPath = new Array(depth).fill(0);
        let tmp = zero;
        for (let i = 0; i < depth; i++) {
            elementPath[i] = tmp;
            tmp = await poseidon2_hash([tmp, 1, 1]);
            tmp = tmp[0];
            i++;
        }

        return new MT(zero, depth, tmp, [tmp], elementPath, indexPath, 0);
    }

    async insert(commitment) {
        // Update the Merkle tree with new commitment
        let new_elementPath = new Array(this.depth).fill(0);
        let new_indexPath = new Array(this.depth).fill(0);
        let tmp = commitment;
        for (let i = 0; i < this.depth; i++) {
            new_elementPath[i] = tmp;
            if (this.indexPath[i] === 0) {
                tmp = await poseidon2_hash([tmp, this.elementPath[i], 1]);
                tmp = tmp[0];
            } else {
                tmp = await poseidon2_hash([this.elementPath[i], tmp, 1]);
                tmp = tmp[0];
            }
        }
        const mt_proof = [this.elementPath, this.indexPath];

        this.root = tmp;
        this.roots.push(this.root);
        this.elementPath = new_elementPath;
        this.index += 1;
        new_indexPath = this.reverseBinaryArray(this.index, this.depth);
        this.indexPath = new_indexPath;

        return [this.root, mt_proof];
    }

    async check_membership(commitment, root, elementPath, indexPath) {
        try {
            // Start with the initial commitment
            let tmp = commitment;

            // Iterate through the Merkle tree depth
            for (let i = 0; i < this.depth; i++) {
                if (indexPath[i] === 0) {
                    // If the indexPath indicates left child, hash (tmp, elementPath[i])
                    tmp = await poseidon2_hash([tmp, elementPath[i], 1]);
                    tmp = tmp[0];
                } else {
                    // Otherwise, hash (elementPath[i], tmp)
                    tmp = await poseidon2_hash([elementPath[i], tmp, 1]);
                    tmp = tmp[0];
                }
            }

            // Check if the root exists in the allowed roots
            if (this.roots.includes(root)) {
                return tmp === root; // Return true if the computed value matches the root
            } else {
                console.warn("Root is not recognised in the set of valid roots.");
                return false; // Indicate failure explicitly
            }
        } catch (error) {
            // Catch and log any unexpected errors
            console.error("Error in check_membership:", error);
            throw error; // Rethrow the error for the caller to handle
        }
    }

    reverseBinaryArray(x, input) {
        // Convert the integer x to its binary representation and pad it to the desired length
        let binaryStr = x.toString(2).padStart(input, '0');

        // Split the binary string into an array of characters, reverse it, and convert back to numbers
        let reversedBinaryArray = Array.from(binaryStr)
            .reverse()
            .map(bit => parseInt(bit, 10));

        return reversedBinaryArray;
    }
}

module.exports = {
    MT
}
