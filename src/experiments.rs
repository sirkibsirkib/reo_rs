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

fn one_run() -> Duration {
    // let (s, r) = std::sync::mpsc::channel::<Whack>();

    let p = FIFO_ARR.build(MemInitial::default()).unwrap();
    let (mut s, mut r) = (
        Putter::<Whack>::claim(&p, "Producer").unwrap(),
        Getter::<Whack>::claim(&p, "Consumer").unwrap(),
    );

    const MOVS: u32 = 25_000;
    let mut taken = Duration::from_millis(0);
    let mut val: MaybeUninit<Whack> = MaybeUninit::new(Whack([3; N]));
    for _ in 0..MOVS {
        let t = Instant::now();
        unsafe {
            s.put_raw(&mut val);
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
            // "M2" => NameDef::Mem(TypeInfo::of::<String>()),
        },
        rules,
    };
    let p = def.build(MemInitial::default().with("M", String::from("Hello!"))).unwrap();
    Getter::<String>::claim(&p, "A").unwrap()
}



#[test]
fn test_4() {
    let values = (0..200 / 5).map(|x| x * 5);
    const REBUILDS: u32 = 100;
    const REPS: u32 = 10_000;

    // use Term::*;
    let bogus = RuleDef {
        state_guard: StatePredicate {
            ready_ports: hashset! { "A" },
            full_mem: hashset! { "M" },
            empty_mem: hashset! { "M2" },
        },
        ins: vec![
            // Instruction::MemSwap("M", "M2"),
            Instruction::Check(Term::False),
        ],
        output: hashmap! { "M2" => (true, hashset!{ "A" }) },
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

#[test]
fn test_5() {
    let mut rules = vec![];
    let putters = ["P0", "P1", "P2"]; //, "P3", "P4"];
    let getters = ["C0", "C1", "C2"]; //, "C3", "C4"];
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
            x.put_lossy(Whack([q as u8; N]));
            taken += i.elapsed();
        }
        taken / REPS
    }

    use rayon::prelude::*;
    let ports: Vec<_> =
        putters.into_iter().map(move |name| Putter::<Whack>::claim(&p, name).unwrap()).collect();

    let start = Instant::now();
    let times: Vec<Duration> = ports.into_par_iter().map(pwork).collect();
    let all = start.elapsed();
    println!("{:?} | {:?}", times, all);
}

// TODO signal demo
// TODO referencey demo

#[test]
pub fn qqwe() {
    let q = Instant::now();
    work_units(Whack([37; N]));
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
    while len < 1 << 13 {
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


// testing getter lock contention when they each fire separate rules
#[test]
fn test_7() {
    let getters = [
        "C0", "C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "C10", "C11", "C12", "C13",
        "C14", "C15", "C16", "C17", "C18", "C19", "C20",
    ];

    const REPS: u32 = 100;
    const RUNS: u32 = 1_000;

    for ports in 1..getters.len() {
        let getter_slice = &getters[..ports];
        let mut totals: Vec<u128> = std::iter::repeat(0).take(ports).collect();
        let type_info = TypeInfo::of::<Whack>();
        for _ in 0..REPS {
            let mut name_defs = hashmap! {"M" => NameDef::Mem(type_info)};
            let d = NameDef::Port { is_putter: false, type_info };
            let mut rules = vec![];

            // always build as if we will use all the getters
            for g in getter_slice.iter().copied() {
                name_defs.insert(g, d.clone());
                let r = RuleDef {
                    state_guard: StatePredicate {
                        ready_ports: hashset! { g },
                        full_mem: hashset! { "M" },
                        empty_mem: hashset! {},
                    },
                    ins: vec![],
                    output: hashmap! {
                        "M" => (true, hashset!{ g }),
                    },
                };
                rules.push(r);
            }
            let def = ProtoDef { name_defs, rules };
            // println!("{:#?}", &def);
            // return;
            let p = def.build(MemInitial::default().with("M", Whack([34; N]))).unwrap();

            use rayon::prelude::*;
            let d: Vec<_> = getter_slice // but then actually initialize just a subset
                .into_par_iter()
                .map(|name: &Name| {
                    let mut x = Getter::<Whack>::claim(&p, name).unwrap();
                    let mut dur = Duration::default();
                    for _ in 0..1000 {
                        x.get(); // warm up
                    }
                    for _ in 0..RUNS {
                        let ins = Instant::now();
                        x.get();
                        dur += ins.elapsed();
                    }
                    for _ in 0..1000 {
                        x.get(); // cool down
                    }
                    dur / RUNS
                })
                .collect();
            for (from, to) in d.into_iter().zip(totals.iter_mut()) {
                *to += from.as_nanos();
            }
        }
        for x in totals.iter_mut() {
            *x /= REPS as u128;
        }
        let mean_tot: u128 = totals.iter().sum::<u128>() / ports as u128;
        // println!("MEAN {:?}\tTOTALS {:?}", mean_tot, totals);
        print!("{:?}, ", mean_tot);
        use std::io::Write;
        std::io::stdout().flush().unwrap();
    }
}


const N: usize = 2048;

pub struct Whack([u8; N]);
impl Default for Whack {
    fn default() -> Self {
        Self([21; N])
    }
}
impl PubPortDatum for Whack {
    const IS_COPY: bool = true;
    fn my_clone2(&self) -> Self {
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
type T8Datum = Whack;
const T8_REPS: u32 = 1_000;
const T8_RUNS: u32 = 3_000;

#[test]
fn test_8() {
    println!("Handmade {:?} | Reo-rs {:?}", test_8a().as_nanos(), "Skipped!");
}

fn test_8a() -> Duration {
    let mut total = Duration::default();
    for _ in 0..T8_REPS {
        let barrier3_g = Arc::new(std::sync::Barrier::new(3));
        let barrier3_p0 = barrier3_g.clone();
        let barrier3_p1 = barrier3_g.clone();

        let (data_0_s, data_0_r) = crossbeam_channel::bounded(0); // rendesvous
        let (data_1_s, data_1_r) = crossbeam_channel::bounded(1); // async

        let p0 = move || {
            barrier3_p0.wait();
            data_0_s.send(T8Datum::default()).unwrap();
        };
        let p1 = move || {
            barrier3_p1.wait();
            data_1_s.send(T8Datum::default()).unwrap();
        };
        let g = move || {
            barrier3_g.wait();
            let _from_p0 = data_0_r.recv().unwrap();
            let _from_p1 = data_1_r.recv().unwrap();
        };
        worky(p0, p1, g, &mut total);
    }
    total / T8_REPS
}

fn test_8b() -> Duration {
    let type_info = TypeInfo::of::<T8Datum>();
    let mut total = Duration::default();
    for _ in 0..T8_REPS {
        let p = ProtoDef {
            name_defs: hashmap! {
                "P0" => NameDef::Port { is_putter:true, type_info },
                "P1" => NameDef::Port { is_putter:true, type_info },
                "G" => NameDef::Port { is_putter:false, type_info },
                "M" => NameDef::Mem(type_info),
            },
            rules: vec![
                RuleDef {
                    state_guard: StatePredicate {
                        ready_ports: hashset! {"P0", "P1", "G"},
                        full_mem: hashset! {},
                        empty_mem: hashset! {"M"},
                    },
                    ins: vec![],
                    output: hashmap! {
                        "P0" => (false, hashset!{"G"}),
                        "P1" => (false, hashset!{"M"}),
                    },
                },
                RuleDef {
                    state_guard: StatePredicate {
                        ready_ports: hashset! {"G"},
                        full_mem: hashset! {"M"},
                        empty_mem: hashset! {},
                    },
                    ins: vec![],
                    output: hashmap! {
                        "M" => (false, hashset!{"G"}),
                    },
                },
            ],
        }
        .build(MemInitial::default())
        .unwrap();

        let (mut p0, mut p1, mut g) = (
            Putter::<T8Datum>::claim(&p, "P0").unwrap(),
            Putter::<T8Datum>::claim(&p, "P1").unwrap(),
            Getter::<T8Datum>::claim(&p, "G").unwrap(),
        );
        let p0 = move || {
            p0.put(T8Datum::default());
        }; 
        let p1 = move || {
            p1.put(T8Datum::default());
        }; 
        let g = move || {
            g.get();
            g.get();
        };

        // let mut p0d = MaybeUninit::new(T8Datum::default());
        // let p0 = move || {
        //     unsafe { p0.put_raw(&mut p0d) };
        // };
        // let mut p1d = MaybeUninit::new(T8Datum::default());
        // let p1 = move || {
        //     unsafe { p1.put_raw(&mut p1d) };
        // };
        // let mut gd = MaybeUninit::uninit();
        // let g = move || unsafe {
        //     g.get_raw(&mut gd);
        //     g.get_raw(&mut gd);
        // };
        worky(p0, p1, g, &mut total)
    }
    total / T8_REPS
}

fn worky<
    P0: 'static + FnMut() + Send,
    P1: 'static + FnMut() + Send,
    G: 'static + FnMut() + Send,
>(
    mut p0: P0,
    mut p1: P1,
    mut g: G,
    total: &mut Duration, 
) {
    const WARMUP: u32 = 100;

    crossbeam_utils::thread::scope(|s| {
        s.spawn(move |_| {
            for _ in 0..(T8_RUNS + WARMUP + WARMUP) {
                // putter 0
                p0();
            }
        });
        s.spawn(move |_| {
            for _ in 0..(T8_RUNS + WARMUP + WARMUP) {
                // putter 1
                p1();
            }
        });
        s.spawn(|_| {
            let mut taken = Duration::default();
            for _ in 0..WARMUP {
                g();
            }
            for _ in 0..T8_RUNS {
                let start = Instant::now();
                g();
                taken += start.elapsed();
            }
            for _ in 0..WARMUP {
                g();
            }
            *total += taken / T8_RUNS;
        });
    }).unwrap();
}
