const buildPoseidon = require("circomlibjs").buildPoseidonOpt;
const { randBetween } = require('bigint-crypto-utils');

async function poseidon_hash(preimage) {
    const poseidonHash = await buildPoseidon(); // Initialize Poseidon hash function
    const hash = poseidonHash.F.toObject(poseidonHash(preimage));
    return hash;
}

function bigint_to_array(n, k, x) {
    let mod = 1n;
    for (let idx = 0; idx < n; idx++) {
        mod = mod * 2n;
    }

    let ret = [];
    let x_temp = x;
    for (let idx = 0; idx < k; idx++) {
        ret.push(x_temp % mod);
        x_temp = x_temp / mod;
    }
    return ret;
}

/**
 * Generate input parameters for Rabin-Miller primality test signals
 * @param {string|number} n - The integer to be checked for primality
 * @param {number} [k] - Number of bases `a`
 * @returns {Object} Object containing `n`, `a`, `d`, and `r`
 */
function generateRabinMillerInput(N, k) {
    if (N < 2n) {
        throw new Error("n must be greater than or equal to 2");
    }

    // Calculate d and r such that n - 1 = d * 2^r, where d is odd
    let d = N - 1n;
    let r = 0;
    while (d % 2n === 0n) {
        d /= 2n;
        r += 1;
    }

    // Generate k random bases a[i] where 2 <= a[i] <= n - 2
    const a = [];
    for (let i = 0; i < k; i++) {
        if (N <= 4n) {
            // When n <= 4, a must be 2
            a.push(2n);
        } else if (N > 2n ** 64n) {
            a.push(randBetween(2n ** 64n, 2n));
        }
        else {
            a.push(randBetween(N - 2n, 2n));
        }
    }

    return {
        n: N,
        a: a,
        d: d,
        r: BigInt(r)
    };
}

function bigintToBitsArray(bigint, bitLength) {
    const bits = [];
    for (let i = 0; i < bitLength; i++) {
        bits.push(Number((bigint >> BigInt(i)) & 1n));
    }
    return bits;
}


module.exports = {
    bigint_to_array,
    generateRabinMillerInput,
    poseidon_hash,
    bigintToBitsArray
}