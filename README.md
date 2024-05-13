
# Differential cryptanalysis of KLEIN

This is an implementation of a differential attack on a round-reduced version of the [KLEIN](https://link.springer.com/chapter/10.1007/978-3-642-25286-0_1) block cipher, achieving key recovery.
The attack is implemented purely in C, with the option to use OpenMP to parallelize the brute-force phase.

![](./media/demo.gif)

On an AMD Ryzen 7 4700U (8 cores), the attack takes around 5 seconds for 5 rounds and around 3 minutes for 6 rounds.

A full report is available [here](report.pdf).

The differential is based on [this paper](https://eprint.iacr.org/2014/090).
The original KLEIN implementation by Gong Zheng is used, which is also available at [this repository](https://github.com/GongZheng/KLEIN).

# Usage

```sh
git clone https://github.com/lcian/klein-cryptanalysis.git
cd klein-cryptanalysis/src
$EDITOR config.h # set the master key and the number of rounds
make
./attack
```
