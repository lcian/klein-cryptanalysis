
# Advanced Topics in Cybersecurity 1

This repository contains my project for the course of "Advanced Topics in Cybersecurity 1" at the University of Klagenfurt.
The project is an implementation of a differential attack on a round-reduced version of the KLEIN block cipher, using the ideas of https://eprint.iacr.org/2014/090.

The implementation of KLEIN (speedklein64.h) is due to Gong Zheng and was taken from https://github.com/GongZheng/KLEIN.

# How to use

- Edit `config.h` to set the number of rounds of KLEIN, the master key, and whether or not you want the key to be printed when running the attack (useful when `random_key` is turned on).
- Adjust the `Makefile` according to the way you want to compile and whether or not you can/want to use OpenMP for parallelism in the bruteforce phase.
- Make and run `attack`.
