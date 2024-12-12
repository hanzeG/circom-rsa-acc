pragma circom 2.1.6;

include "../blockchain_ZKPs/circom/rabin_miller.circom";

// Instantiate RabinMillerPrimalityTest with 5 bases and 128-bit exponentiation, max 10 rounds
component main {public [n, a]} = RabinMillerPrimalityTest(5, 128, 10);