# Known Issues

2. Doesn't compile properly when dynamically linked using MinGW linker on Windows OS.


1. Not all of the Port API has been given a suitable C-friendly API surface. Solving this is just a matter of investing the time to do it.


1. cbindgen isn't integrated yet. Once done, the C FFI can be maintained in a safer, more automated fashion.

1. C++ programs must use ReoRs via the C ABI instead of directly for the time being. Integration with cbindgen will speed this along.


3. Rust unit tests emulating the C FFI encounter faults when a thread begins to panic. To be investigated. (Guess: Related to double-frees).



1. There is no canonical way for a Rust program to depend on another Rust program via dynamic linkage as the Rust ABI is unstable. It is possible to do this via the C ABI, but this prohibits many of Rust's best features: generics etc.



5. The type reflection implementation is brittle; some circumstances lead to false positives in type equality checks (eg in `Putter::claim`). This is not a threat to safety, but generates erroneous error cases. Some causes are predictable: Eg: redundantly linking two versions of ReoRS as a DLL will duplicate virtual function tables. 

1. Reo compiler does not currently generate `FromStr` dependencies correctly. (eg: type `T0` requires additional constraint on the function `<T0 as std::str::FromStr>::Err: std::fmt::Debug`)

