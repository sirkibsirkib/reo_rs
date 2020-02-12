# ReoRs



An implementation of system components to enforce adherence to a protocol with respect to data flowing through logical ports. These protocol components are able to act as a _communication medium_ for threads sending and receiving data. On its own, this is useful is facilitating data-flow as desired. However, the real utlility of these components is their preservation of their corresponding _protocol specification_ in the [Reo language](http://reo.project.cwi.nl).

The library can be used in a stand-alone fashion (See examples below) but is built with the Reo Compiler in mind. The details of the implementation and the association with Reo are documented in detail as part of my [master's thesis](https://github.com/sirkibsirkib/msc_latex/blob/master/main.pdf). 

## Standalone Use
This library is standalone, and can be imported and used as a Rust dependency in the usual way with or without Reo's code generation. The library requires the use of a _nightly_ compiler to leverage two of Rust's experimental features (see the thesis for more details). Once these features become stable, the library will be made available on Crates.io as is the Rust convention.

In the meantime, Reo-rs can be integrated into a Rust crate as a path or Github dependency. See [this](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html) for up-to-date instructions. At time of writing, a github dependency is ergonomic, requiring only the following line to the dependency section of your Cargo.toml: `reo_rs = { git = "https://github.com/sirkibsirkib/reo_rs" }`.

## Protocol Objects
At runtime, `Proto` objects do the work. Instances of this type are acquired from the `ProtoDef::build` method, which ensures they are initialized correctly. In this manner, the user is only responsible for providing a `ProtoDef` structure. For example, the canonical Reo [alternator](http://reo.project.cwi.nl/v2/#examples-of-complex-connectors) connector can be defined as:

```rust
ProtoDef {
    name_defs: hashmap! {
        "A" => NameDef::Port { is_putter:true , type_info: TypeInfo::of::<u32>() },
        "B" => NameDef::Port { is_putter:true , type_info: TypeInfo::of::<u32>() },
        "C" => NameDef::Port { is_putter:false, type_info: TypeInfo::of::<u32>() },
        "M" => NameDef::Mem(TypeInfo::of::<u32>()),
    },
    rules: vec![
        RuleDef {
            state_guard: StatePredicate {
                ready_ports: hashset! {"A", "B", "C"},
                full_mem:  hashset! {},
                empty_mem: hashset! {"M"},
            },
            ins: vec![],
            output: hashmap! { "A" => (false, hashset!{"C"}),
                               "B" => (false, hashset!{"M"}) },
        },
        RuleDef {
            state_guard: StatePredicate {
                ready_ports: hashset! {"C"},
                full_mem:  hashset! {"M"},
                empty_mem: hashset! {},
            },
            ins: vec![],
            output: hashmap! { "M" => (false, hashset!{"C"}) },
        },
    ],
}

```

This example demonstrates that nothing is stopping you from making protocol components by hand, but they are verbose and intricate. The [Reo Compiler](http://reo.project.cwi.nl) is able to generate these definitions from more human-friendly Reo specifications.

## Playground
See the `/playground/` for a walkthrough of how this library may be used

## Compiling for C
Your Rust code can be leveraged in your C programs by relying on the C ABI. The Reo compiler will emit Rusty protocol code already prepared for this. If you aren't familiar with Rust, the script `rs_to_so.sh` is provided.


