# Breaking \#100 (`hopeful_kirch`)

This folds contains our break of `hopeful_kirch`, the \#100 challenge submitted to [WhibOx 2019](https://whibox-contest.github.io/2019/).

The organization of this folder is as following:

- [1_origin](1_origin): Original source code of \#100.
- [2_de-obfuscated](2_de-obfuscated): De-obfuscated code.
- [3_de-obfuscated-single-slot](3_de-obfuscated-single-slot): Further de-obfuscated by only keeping the good execution slot.
- [4_correct-slot-attack](4_correct-slot-attack): Our final attack, please read the [`README.md`](4_correct-slot-attack/README.md) in this folder for how to attack.

Each folder above has a `Makefile`, which is used to create the executable.
