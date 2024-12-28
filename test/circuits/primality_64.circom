pragma circom 2.1.6;

include "../../circuits/rm_primality.circom";

// Instantiate RabinMillerPrimalityTest with 5 bases and 64-bit exponentiation, max 10 rounds
component main {public [n, a]} = RabinMillerPrimalityTest(5, 64, 10);