# ReoRs C Example

This represents a small example use case of Reo being used to coordinate data 
flow in a C program. Initially, the library file `fifo1.so` is missing. 
This can be acquired by executing the Reo compiler on the given `fifo1.rba.treo` file, and placing it in the same directory. The Reo compiler's source code can be acquired from its [Github repository](https://github.com/ReoLanguage/Reo) to produce a dynamically-linked library `fifo1.so`.

*Note*: The resulting library is hightly platform-specific. For this reason it's not very practical to provide it directly.

The finished binary is acquired by running the simple build script provided, `make.sh`, resulting in the executable file `main`. Feel free to play around with the contents of `main.c` and with the protocol definition. 

*Note* C does not provide the same type- and memory-safety guarantees of Rust. It is very easy to shoot yourself in the foot by making a mistake here.