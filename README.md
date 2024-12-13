# Implementation of RSA-based Stealth Address

This repository provides an implementation of a Zero-Knowledge Proof for the RSA accumulator algorithm in the [Circom](https://docs.circom.io) language. It supports a tumbler based on an incremental Merkle tree UTXO model, enabling non-interactive [stealth address](https://hinkal-team.gitbook.io/hinkal/hinkal/setup/keys-and-shielded-addresses) functionality. For reference, the interactive stealth address functionality implemented by [Hinkal](https://hinkal-team.gitbook.io/hinkal) can be considered. This tumbler provides the following functionalities: private external transfers, private internal transfers, and private withdrawals.

Specifically, private external transfers allow a sender to transfer funds to a recipient who has already registered an account in the tumbler, without the sender needing to register or deposit in advance. These transactions are unlinkable between the sender and the recipient. Private internal transfers or withdrawals allow a sender to secretly spend their UTXOs held by the tumbler to either withdraw funds or transfer them to another registered user (generating a new UTXO). Both transaction types maintain unlinkability.

The circuit templates under the circuits directory currently support functionalities such as modular exponentiation for arbitrary large integers, verification of a secret’s membership in an RSA accumulator based on \phi(N), and Merkle tree membership proof algorithms. Tests for these algorithms, including the tumbler’s business logic circuit templates, are provided under the test directory.

# Getting started

To run the circuit test cases:

```sh
git submodule update --init --recursive
```
```sh
cd blockchain_ZKPs; npm i; cd ..; npm i; npm test
```

[blockchain_ZKP]((https://github.com/badblood8/blockchain_ZKPs)) is a library implemented in Circom for primality testing algorithms, and [circom-ecdsa](https://github.com/0xPARC/circom-ecdsa) provides circuit templates for modular exponentiation of large integers with fixed exponent sizes (non-input signals), among other functionalities.

## Circuits Benchmark

* Mac (Apple M1 Pro, 2021), 10-core CPU, 16GB RAM
<!-- * Proof system: Groth16 -->

| Test Case               | Template Instances | Non-linear Constraints | Linear Constraints | Public Inputs | Private Inputs           | Public Outputs | Wires     | Labels    |
| ----------------------- | ------------------ | ---------------------- | ------------------ | ------------- | ------------------------ | -------------- | --------- | --------- |
| spend.circom            | 101                | 6,147,001              | 1                  | 0             | 143                      | 1              | 6,105,363 | 6,760,823 |
|                         |
| verify_wtns.circom      | 24                 | 6,118,977              | 1                  | 0             | 97                       | 1              | 6,077,315 | 6,722,533 |
|                         |
| pow_mod_1024_64.circom  | 22                 | 1,533,729              | 0                  | 0             | 33                       | 16             | 1,523,138 | 1,685,955 |
|                         |
| pow_mod_1024_128.circom | 23                 | 3,067,489              | 0                  | 0             | 33                       | 16             | 3,046,274 | 3,371,843 |
|                         |
| pow_mod_2048_64.circom  | 22                 | 3,059,457              | 0                  | 0             | 65                       | 32             | 3,038,658 | 3,361,283 |
|                         |
| pow_mod_2048_128.circom | 23                 | 6,118,977              | 0                  | 0             | 65                       | 32             | 6,077,314 | 6,722,435 |
|                         |
| primality.circom        | 3                  | 6,414                  | 0                  | 6             | 2 (1 belongs to witness) | 1              | 6,382     | 26,095    |

