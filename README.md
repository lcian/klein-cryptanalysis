
# Advanced Topics in Cybersecurity 1

This repository contains my project for the course of "Advanced Topics in Cybersecurity 1" at the University of Klagenfurt.

The project is an implementation of a differential attack on a round-reduced version of the KLEIN block cipher, using the ideas of [this paper](https://eprint.iacr.org/2014/090).
OpenMP is used to parallelize the bruteforce phase to recover the higher nibbles.

You can read the report [here](report.pdf), where I explain the attack and its computational complexity.

The implementation of KLEIN (speedklein64.h) is due to Gong Zheng and was taken from [this repository](https://github.com/GongZheng/KLEIN).

# How to use

- change directory into `src`;
- edit `config.h` to set the number of rounds of KLEIN, the master key, and whether or not you want the key to be printed when running the attack (useful if `random_key` is turned on);
- adjust the `Makefile` according to the way you want to compile (if you don't have/want OpenMP, just remove `-fopenmp`);
- make and run `attack`.
