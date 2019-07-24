use super::*;

lazy_static::lazy_static! {
    static ref FIFO_ARR: ProtoDef = ProtoDef {
        name_defs: hashmap! {
            "Producer" => NameDef::Port { is_putter:true, type_info: TypeInfo::of::<Whack>() },
            "Consumer" => NameDef::Port { is_putter:false, type_info: TypeInfo::of::<Whack>() },
            "Memory" => NameDef::Mem(TypeInfo::of::<Whack>()),
        },
        rules: vec![RuleDef {
            state_guard: StatePredicate {
                ready_ports: hashset! {"Producer"},
                full_mem: hashset! {},
                empty_mem: hashset! {"Memory"},
            },
            ins: vec![],
            output: hashmap! {
                "Producer" => (false, hashset!{"Memory"})
            },
        },
        RuleDef {
            state_guard: StatePredicate {
                ready_ports: hashset! {"Consumer"},
                full_mem: hashset! {"Memory"},
                empty_mem: hashset! {},
            },
            ins: vec![],
            output: hashmap! {
                "Memory" => (false, hashset!{"Consumer"})
            },
        }],
    };
}

const N: usize = 1 << 1;

fn one_run() -> Duration {
    // let (s, r) = std::sync::mpsc::channel::<Whack>();

    let p = FIFO_ARR.build(MemInitial::default()).unwrap();
    let (mut s, mut r) = (
        Putter::<Whack>::claim(&p, "Producer").unwrap(),
        Getter::<Whack>::claim(&p, "Consumer").unwrap(),
    );

    const MOVS: u32 = 25_000;
    let mut taken = Duration::from_millis(0);
    let mut val: MaybeUninit<Whack> = MaybeUninit::new(Whack([3;N]));
    for _ in 0..MOVS {
        let t = Instant::now();
        unsafe {
            s.put_raw(val.as_mut_ptr());
        };
        r.get();
        taken += t.elapsed();
    }
    taken / MOVS
}

use std::time::{Duration, Instant};
#[test]
fn test_1() {
    let mut taken = Duration::from_millis(0);
    const REPS: u32 = 10;
    for _ in 0..REPS {
        taken += one_run();
    }
    println!("{:?}", taken / REPS);
}

#[test]
fn test_2() {
    let mut tot = Duration::from_millis(0);
    const REPS: u32 = 10;

    for _ in 0..REPS {
        let def = ProtoDef {
            name_defs: hashmap! {
                "P" => NameDef::Port { is_putter:true, type_info: TypeInfo::of::<Whack>() },
                "C0" => NameDef::Port { is_putter:false, type_info: TypeInfo::of::<Whack>() },
                "C1" => NameDef::Port { is_putter:false, type_info: TypeInfo::of::<Whack>() },
                "C2" => NameDef::Port { is_putter:false, type_info: TypeInfo::of::<Whack>() },
                "C3" => NameDef::Port { is_putter:false, type_info: TypeInfo::of::<Whack>() },
                "C4" => NameDef::Port { is_putter:false, type_info: TypeInfo::of::<Whack>() },
            },
            rules: vec![RuleDef {
                state_guard: StatePredicate {
                    ready_ports: hashset! {"P", "C0", "C1", "C2", "C3", "C4"},
                    full_mem: hashset! {},
                    empty_mem: hashset! {},
                },
                ins: vec![],
                output: hashmap! {
                    "P" => (false, hashset!{"C0", "C1", "C2", "C3", "C4"})
                },
            }],
        };

        let p = def.build(MemInitial::default()).unwrap();

        const FIRINGS: u32 = 5_000 + 1;

        use crossbeam_utils::thread;
        let work = |name: &'static str| {
            let mut g = Getter::<Whack>::claim(&p, name).unwrap();
            for _ in 0..FIRINGS {
                g.get();
            }
        };
        thread::scope(|s| {
            s.spawn(|_| {
                // ensure getters are ready
                // std::thread::sleep(Duration::from_millis(30));
                let mut taken = Duration::from_millis(0);
                let mut p = Putter::<Whack>::claim(&p, "P").unwrap();
                for i in 0..FIRINGS {
                    let before = Instant::now();
                    p.put(Whack([i as u8; N]));
                    if i > 0 {
                        taken += before.elapsed();
                    }
                }
                tot += taken / (FIRINGS - 1);
            });
            s.spawn(|_| work("C0"));
            s.spawn(|_| work("C1"));
            s.spawn(|_| work("C2"));
            s.spawn(|_| work("C3"));
            s.spawn(|_| work("C4"));
        })
        .unwrap();
    }
    println!("TOOK AVG {:?} ns", (tot / REPS as u32).as_nanos());
}

#[test]
fn test_3() {
    let mut tot = Duration::from_millis(0);
    const REPS: u32 = 10;

    for _ in 0..REPS {
        let def = ProtoDef {
            name_defs: hashmap! {
                "P" => NameDef::Port { is_putter:true, type_info: TypeInfo::of::<Whack>() },
                "C0" => NameDef::Port { is_putter:false, type_info: TypeInfo::of::<Whack>() },
                "C1" => NameDef::Port { is_putter:false, type_info: TypeInfo::of::<Whack>() },
                "C2" => NameDef::Port { is_putter:false, type_info: TypeInfo::of::<Whack>() },
                "C3" => NameDef::Port { is_putter:false, type_info: TypeInfo::of::<Whack>() },
                "C4" => NameDef::Port { is_putter:false, type_info: TypeInfo::of::<Whack>() },
            },
            rules: vec![RuleDef {
                state_guard: StatePredicate {
                    ready_ports: hashset! {
                        "P",
                        "C0",
                        "C1",
                        "C2",
                        "C3",
                        "C4",
                    },
                    full_mem: hashset! {},
                    empty_mem: hashset! {},
                },
                ins: vec![],
                output: hashmap! {
                    "P" => (false, hashset!{
                        "C0",
                        "C1",
                        "C2",
                        "C3",
                        "C4",
                   })
                },
            }],
        };

        let p = def.build(MemInitial::default()).unwrap();

        const FIRINGS: u32 = 1_000 + 1;

        use crossbeam_utils::thread;
        let work = |name: &'static str| {
            let mut g = Getter::<Whack>::claim(&p, name).unwrap();
            for _ in 0..FIRINGS {
                g.get();
            }
        };
        thread::scope(|s| {
            s.spawn(|_| {
                // ensure getters are ready
                // std::thread::sleep(Duration::from_millis(30));
                let mut taken = Duration::from_millis(0);
                let mut p = Putter::<Whack>::claim(&p, "P").unwrap();
                for i in 0..FIRINGS {
                    let before = Instant::now();
                    p.put(Whack([i as u8; N]));
                    if i > 0 {
                        taken += before.elapsed();
                    }
                }
                tot += taken / (FIRINGS - 1);
            });
            s.spawn(|_| work("C0"));
            s.spawn(|_| work("C1"));
            s.spawn(|_| work("C2"));
            s.spawn(|_| work("C3"));
            s.spawn(|_| work("C4"));
        })
        .unwrap();
    }
    println!("TOOK AVG {:?} ns", (tot / REPS as u32).as_nanos());
}

fn make(num_bogus: usize, bogus_rule: &RuleDef) -> Getter<String> {
    let mut rules = vec![];
    let legit = RuleDef {
        state_guard: StatePredicate {
            ready_ports: hashset! { "A" },
            full_mem: hashset! { "M" },
            empty_mem: hashset! {},
        },
        ins: vec![],
        output: hashmap! { "M" => (true, hashset!{ "A" }) },
    };
    for _ in 0..num_bogus {
        rules.push(bogus_rule.clone());
    }
    rules.push(legit);
    let def = ProtoDef {
        name_defs: hashmap! {
            "A" => NameDef::Port { is_putter:false, type_info: TypeInfo::of::<String>() },
            "Bogus" => NameDef::Port { is_putter:false, type_info: TypeInfo::of::<String>() },
            "M" => NameDef::Mem(TypeInfo::of::<String>()),
        },
        rules,
    };
    let p = def.build(MemInitial::default().with("M", String::from("Hello!"))).unwrap();
    Getter::<String>::claim(&p, "A").unwrap()
}

#[test]
fn test_4() {
    let values = (0..200 / 5).map(|x| x * 5);
    const REBUILDS: u32 = 50;
    const REPS: u32 = 1_000;

    use Term::*;
    let bogus = RuleDef {
        state_guard: StatePredicate {
            ready_ports: hashset! { "A" },
            full_mem: hashset! { "M" },
            empty_mem: hashset! {},
        },
        ins: vec![Instruction::Check {
            term: And(vec![
                And(vec![True, True, True, True, True]),
                And(vec![True, True, True, True, True]),
                And(vec![True, True, True, True, True]),
                And(vec![True, True, True, True, True]),
                And(vec![True, True, True, True, False]),
            ]),
        }],
        output: hashmap! { "M" => (true, hashset!{ "A" }) },
    };

    for v in values {
        let mut taken = Duration::default();
        for _ in 0..REBUILDS {
            let mut g = make(v, &bogus);
            for _ in 0..REPS {
                let x = Instant::now();
                let val = g.get();
                taken += x.elapsed();
                drop(val);
            }
        }
        taken /= REBUILDS * REPS;
        print!("{}, ", taken.as_nanos());
        use std::io::Write;
        std::io::stdout().flush().unwrap();
    }
}


pub struct Whack([u8; N]);
impl PubPortDatum for Whack {
    const IS_COPY: bool = true;
    fn my_clone2(&self) -> Self {
        // const CLONE_NANOS: u64 = 10000;
        // std::thread::sleep(Duration::from_nanos(CLONE_NANOS));
        // println!("CLONEY");
        let mut x = self.0.clone();
        for i in 0..10_000_usize {
            for val in x.iter_mut() {
                *val %= 11;
                *val *= ((i % 7) as u8) + 1;
            }
        }
        Self(x)
    }
    fn my_eq2(&self, _other: &Self) -> bool {
        true
    }
}


#[test]
fn test_5() {
    let mut rules = vec![];
    let putters = ["P0", "P1", "P2"];//, "P3", "P4"];
    let getters = ["C0", "C1", "C2"];//, "C3", "C4"];
    for putter in putters.iter().copied() {
        for getter in getters.iter().copied() {
            let rule = RuleDef {
                state_guard: StatePredicate {
                    ready_ports: hashset! { putter, getter },
                    full_mem: hashset! {},
                    empty_mem: hashset! {},
                },
                ins: vec![],
                output: hashmap! { putter => (false, hashset!{ getter }) },
            };
            rules.push(rule);
        }
    }
    let def = ProtoDef {
        name_defs: hashmap! {
            "P0" => NameDef::Port { is_putter:true, type_info: TypeInfo::of::<Whack>() },
            "P1" => NameDef::Port { is_putter:true, type_info: TypeInfo::of::<Whack>() },
            "P2" => NameDef::Port { is_putter:true, type_info: TypeInfo::of::<Whack>() },
            // "P3" => NameDef::Port { is_putter:true, type_info: TypeInfo::of::<Whack>() },
            // "P4" => NameDef::Port { is_putter:true, type_info: TypeInfo::of::<Whack>() },
            "C0" => NameDef::Port { is_putter:false, type_info: TypeInfo::of::<Whack>() },
            "C1" => NameDef::Port { is_putter:false, type_info: TypeInfo::of::<Whack>() },
            "C2" => NameDef::Port { is_putter:false, type_info: TypeInfo::of::<Whack>() },
            // "C3" => NameDef::Port { is_putter:false, type_info: TypeInfo::of::<Whack>() },
            // "C4" => NameDef::Port { is_putter:false, type_info: TypeInfo::of::<Whack>() },
        },
        rules,
    };

    const REPS: u32 = 100_000;
    let p = def.build(MemInitial::default()).unwrap();

    for getter in getters.iter().copied() {
        let mut x = Getter::<Whack>::claim(&p, getter).unwrap();
        std::thread::spawn(move || loop {
            x.get();
        });
    }

    fn pwork(mut x: Putter<Whack>) -> std::time::Duration {
        let mut taken = Duration::default();
        for q in 0..REPS {
            let i = Instant::now();
            x.put_lossy(Whack([q as u8;N]));
            taken += i.elapsed();
        }
        taken / REPS
    }

    use rayon::prelude::*;
    let ports: Vec<_> = putters
        .into_iter()
        .map(move |name| Putter::<Whack>::claim(&p, name).unwrap())
        .collect();

    let start = Instant::now();
    let times: Vec<Duration> = ports
        .into_par_iter()
        .map(pwork)
        .collect();
    let all = start.elapsed();
    println!("{:?} | {:?}", times, all);
}

// TODO signal demo
// TODO referencey demo


#[test]
pub fn qqwe() {
    let q = Instant::now();
    work_units(Whack([37;N]));
    let x = q.elapsed();
    println!("{:?}", x);
}

#[inline(never)]
pub fn work_units(mut x: Whack) -> Whack {
    for i in 0..10_000usize {
        for val in x.0.iter_mut() {
            *val %= 11;
            *val *= ((i % 7) as u8) + 1;
        }
    }
    x
}


#[test]
fn test_6() {
    let mut rng = rand::thread_rng();
    const REPS: u32 = 100;

    let mut len = 1;
    while len < 1<<13 {
        let mut x = [Duration::default(); 2];
        for _ in 0..REPS {
            let [y0, y1] = go(&mut rng, len, 0.5);
            x[0] += y0;
            x[1] += y1;
        }
        x[0] /= REPS;
        x[1] /= REPS;
        print!("{:?}, ", x[0].as_nanos());
        use std::io::Write;
        std::io::stdout().flush().unwrap();
        len <<= 1;
    }
}

fn go<R: rand::Rng>(rng: &mut R, len: usize, fullness: f32) -> [Duration; 2] {
    use rand::distributions::Distribution;
    let uni = rand::distributions::Uniform::from(0..len);
    let samples = (len as f32 * fullness) as usize;

    let x: HashSet<LocId> = (0..samples).map(|_| uni.sample(rng)).map(LocId).collect();


    let a = Instant::now();
    x.is_subset(&x);
    let a = a.elapsed();

    let x: BitSet = x.into_iter().collect();


    let b = Instant::now();
    x.is_subset(&x);
    let b = b.elapsed();
    [a, b]
}
