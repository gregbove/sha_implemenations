# sha_implemenations
This implementation of SHA-256 and SHA-224 aims to improve the performance of the message digest calculation by reordering calculations so they they can be better parallelized with fewer hardware resources. This will be implemented on a Nexy's A-7 FPGA chip by using Vitis HLS to generate RTL code from this C code.
