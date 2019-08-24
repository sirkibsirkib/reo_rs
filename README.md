# Reo-rs
## What is this?

Rust auxiliary library depended upon by [Reo](http://reo.project.cwi.nl)-generated Rust code.
Contributed as part of my master's thesis, available [here](https://github.com/sirkibsirkib/msc_latex).

## How to use it
This library is standalone, and can be imported and used as a Rust dependency in the usual way with or without Reo's code generation.
At time of writing, this library is NOT yet available on crates.io. Currently, one requires the nightly compiler to use Reo-rs, as it relies upon two unstable language features (see the thesis for more details). Once these land in stable, I'll clean up the unsafe features and publish it to crates.io as is the convention.

In the meantime, Reo-rs can be used as a path or Github dependency. See [this](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html) for up-to-date instructions.

