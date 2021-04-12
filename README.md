# P4 Flow Cache

This repository hosts the P4 code of the Flow Cache use case.

In particular, the files are structured as follows:

- *flowcache.p4* contains the P4 code implementing the Flow Cache use case, employing the extended P4 language constructs needed to describe the per-flow stateful extensions.
- *flowcache_IR.p4* contains the *standard* P4 code that does not employ the *extended* P4 constructs. It is used to be compiled with the P4 compile (p4c) whose compiled output is used as a scaffold. In fact, we exploit this *intermediate* compiled version to manually add in the JSON the stateful extensions in order to configure the extended bmv2 software switch with the stateful primitives.
- *flowcache_IR_hacked.json* is the manually modified JSON used to configure the extended bmv2 implementation.

## DEMO video

A video of the DEMO is available below:

[![video](https://img.youtube.com/vi/yCXyGv3n9sk/0.jpg)](https://www.youtube.com/watch?v=yCXyGv3n9sk)
