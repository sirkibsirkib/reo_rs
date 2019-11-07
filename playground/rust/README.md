# ReoRs Rust Example

This crate represents a user program. The general-purpose Reo behavior is 
provided by the dependency on `reo_rs`, providing types and methods for 
protcols in general (eg: type `Putter`).

The file `src/fifo1.rs` represents the output of the Reo compiler. It does nothing more than provide a function that _constructs_ a particular protocol (in this case the _fifo1_ connector for data of type `isize`).

Feel free to play around with the contents of `src/main.rs`. Try some other protocols avalable in `playground/example_generated`.