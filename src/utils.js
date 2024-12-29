const buildPoseidon = require("circomlibjs").buildPoseidonOpt;
const { randBetween } = require('bigint-crypto-utils');
const poseidon2Constants = require("./poseidon2_constants.js");
const { utils, getCurveFromName } = require("ffjavascript");
const { MAT_DIAG3_M_1, MAT_INTERNAL3, RC3 } = utils.unstringifyBigInts(poseidon2Constants);
const { Poseidon2, F1Field } = require("poseidon2");

async function poseidon_hash(preimage) {
    const poseidonHash = await buildPoseidon(); // Initialize Poseidon hash function
    const hash = poseidonHash.F.toObject(poseidonHash(preimage));
    return hash;
}

async function poseidon2_hash(preimage) {
    const prime = await getCurveFromName("bn128", true);
    const F = new F1Field(prime.r);
    const poseidon2 = new Poseidon2(
        getPoseidon2Params(3, 5, 8, 56, MAT_DIAG3_M_1, MAT_INTERNAL3, RC3), F
    );
    return poseidon2.permute(preimage.map(x => BigInt(x)));
}

// call this function with your parameters from sage/horizen labs' precomputed constants
function getPoseidon2Params(
    t,
    d,
    rounds_f,
    rounds_p,
    mat_internal_diag_m_1,
    mat_internal,
    round_constants
) {
    const r = rounds_f / 2;
    const rounds = rounds_f + rounds_p;
    return {
        t: t,
        d: d,
        rounds_f_beginning: r,
        rounds_p: rounds_p,
        rounds_f_end: r,
        rounds: rounds,
        mat_internal_diag_m_1: mat_internal_diag_m_1,
        _mat_internal: mat_internal,
        round_constants: round_constants,
    };
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
        } else if (N > 2n ** 16n) {
            a.push(randBetween(2n ** 16n, 2n));
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

function rotateRight(arr, positions) {
    const len = arr.length;
    const offset = positions % len;
    if (offset === 0) return arr.slice();

    return arr.slice(-offset).concat(arr.slice(0, len - offset));
}

function swap(arr, index1, index2) {
    let newArr = [...arr];
    [newArr[index1], newArr[index2]] = [newArr[index2], newArr[index1]];

    return newArr;
}

module.exports = {
    bigint_to_array,
    generateRabinMillerInput,
    poseidon_hash,
    poseidon2_hash,
    bigintToBitsArray,
    rotateRight,
    swap
}