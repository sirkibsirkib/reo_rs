use crate::TypeInfo;
use crate::outer::Name;
use std::collections::HashMap;
use std::sync::Arc;
use std::any::TypeId;
use std::mem::{MaybeUninit, transmute};

type Ptr = *mut u8;

type Bogus = Outputter<()>;
pub enum CallHandle {
    // when invoking, be sure types agree again
    A0((TypeInfo, [TypeInfo;0]), fn(Bogus, [Bogus;0]) -> Committed),
    A1((TypeInfo, [TypeInfo;1]), fn(Bogus, [Bogus;1]) -> Committed),
}
pub struct Outputter<T>(*mut T);
impl<T> Outputter<T> {
    #[inline]
    pub fn output(self, t: T) -> Committed {
        unsafe {
            println!("writing to {:p}", self.0);
            self.0.write(t);
            transmute(())
        }
    }
}

pub struct Fulfilled {}
pub struct Committed {}
pub struct FuncDefPromise<'a> {
    name: Name,
    builder: &'a mut ProtoBuilder,
}
impl FuncDefPromise<'_> {
    fn def_nonary<R: 'static>(
        self,
        callable: fn(Outputter<R>) -> Committed,
    ) -> Fulfilled {
        let callable = unsafe { std::mem::transmute(callable) }; 
        let handle = CallHandle::A0((TypeInfo::of::<R>(), []), callable);
        self.builder.func_defs.insert(self.name, handle);
        unsafe { transmute(()) }
    }
    fn def_unary<R: 'static, A0: 'static>(
        self,
        callable: fn(Outputter<R>, &A0) -> Committed,
    ) -> Fulfilled {
        let callable = unsafe { transmute(callable) }; 
        let handle = CallHandle::A1((TypeInfo::of::<R>(), [TypeInfo::of::<A0>()]), callable);
        self.builder.func_defs.insert(self.name, handle);
        unsafe { transmute(()) }
    }
}

pub struct ProtoBuilder {
    func_defs: HashMap<Name, CallHandle>,
}

use maplit::hashmap;

#[test]
pub fn testy() {
    let mut pb = ProtoBuilder {
        func_defs: hashmap!{},
    };
    let fdp = FuncDefPromise { name: "sam", builder: &mut pb };
    fdp.def_nonary(|c| c.output(0u32));

    let fdp = FuncDefPromise { name: "sam2", builder: &mut pb };
    fdp.def_unary(|c, a: &u32| {
        let x: u32 = *a + 2;
        c.output(x)
    });


    let a = pb.func_defs.get("sam2").unwrap();

    let mut val = 2u32;
    let paral = 3u32;
    println!("{:p}", &val);
    let c = Outputter(&mut val);
    unsafe {
            match a {
            CallHandle::A0(a, b) => {
                b(transmute(c), []);
            }
            CallHandle::A1(a, b) => {
                b(transmute(c), [transmute(&paral)]);
            }
        }
    }
    println!("val {:?}", val);
}


