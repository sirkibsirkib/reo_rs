# ReoRs Playground

In this section we will walk through the use of the Reo compiler to generate protocol objects that can coordinate data flow in your Rust and C programs. Under the hood, the Rust compiler prepares this dependency. Before beginning, ensure that Rust _nightly_ is installed (see the [webpage](https://www.rust-lang.org/learn/get-started)). Version 1.28 or newer is recommended.

The process for either Rust or C begins with the Reo compiler given some textual Reo definition `X.treo` as input (where X is the name of your protocol). The output language depends on the language flag passed to the Reo compiler. 

# Rust Output
The Reo compiler outputs a single file: `X.rs`. This is a source file which can be incorporated into a Rust codebase in the usual way. It depends on two libraries in total:
1. reo_rs (this)
2. maplit (available on crates.io).

See `./rust/` for more.

# C Output
The Reo compiler outputs two files: `X.so`. This dynamically-linked library defines the behavior in the declarations given in the header file available in the repository [here](https://github.com/sirkibsirkib/reo_rs/reo_rs_ext.h). The latter must appear in your source, and the former can be linked later.

*Note*: Installing Rust can be avoided in the case of C programs by acquiring `X.so` file from elsewhere provided it is compiled under suitable circumstances.

See `./c/` for more.

## Known issues
1. The C API does not protect you from type unsafety and uninitialized memory as the Rust API does. As C lacks generics, all ports unify their disparate datatypes by passing them indirectly (as the void* type). The user is responsible for ensuring they are cast correctly once again on the other side.

2. Currently there can only be one Reo-generated C file per program. This is not a shortcoming of Reo, but a shortcoming in Rust's ability to dynamically link Rust dependencies. 


