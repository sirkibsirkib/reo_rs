use super::*;
use core::{fmt::Debug, mem::MaybeUninit};

pub type ArcProto = *const Proto;

#[repr(C)]
#[derive(Default)]
pub struct ErrBuf(pub String);

impl ErrBuf {
    fn map_or_write<T, E: Debug>(&mut self, res: Result<T, E>) -> Option<T> {
        self.0.clear();
        match res {
            Ok(x) => Some(x),
            Err(x) => {
                use std::fmt::Write;
                write!(&mut self.0, "{:?}", x).unwrap();
                None
            }
        }
    }
}

unsafe fn finalize<R, E: Debug>(
    out: &mut MaybeUninit<R>,
    err_buf: &mut ErrBuf,
    res: Result<R, E>,
    finally: impl FnOnce(),
) -> bool {
    let x = if let Some(o) = err_buf.map_or_write(res) {
        out.as_mut_ptr().write(o);
        true
    } else {
        false
    };
    finally();
    x
}

///////// NEW

#[no_mangle]
pub unsafe extern "C" fn reors_putter_claim(
    p: ArcProto,
    name: Name,
    out: &mut MaybeUninit<Putter>,
    err_buf: &mut ErrBuf,
) -> bool {
    let p = Arc::from_raw(p);
    finalize(out, err_buf, Putter::claim_raw(&p, name), move || {
        Arc::into_raw(p);
    })
}

#[no_mangle]
pub unsafe extern "C" fn reors_getter_claim(
    p: ArcProto,
    name: Name,
    out: &mut MaybeUninit<Getter>,
    err_buf: &mut ErrBuf,
) -> bool {
    let p = Arc::from_raw(p);
    finalize(out, err_buf, Getter::claim_raw(&p, name), move || {
        Arc::into_raw(p);
    })
}
#[no_mangle]
pub unsafe extern "C" fn reors_err_buf_new() -> Box<ErrBuf> {
    Box::new(Default::default())
}
#[no_mangle]
pub unsafe extern "C" fn reors_proto_clone(p: ArcProto) -> ArcProto {
    Arc::into_raw(Arc::from_raw(p))
}

///////// USE

#[no_mangle]
pub unsafe extern "C" fn reors_read_err(err_buf: &ErrBuf, len: &mut usize) -> *const u8 {
    let bytes = err_buf.0.as_str().as_bytes();
    *len = bytes.len();
    bytes.as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn reors_put(putter: &mut Putter, msg: *mut u8) -> bool {
    putter.put_raw(msg)
}

#[no_mangle]
/// NULL msg pointer will not be written to
pub unsafe extern "C" fn reors_get(putter: &mut Getter, msg: *mut u8) {
    putter.get_raw(msg)
}

///////// DESTROY
#[no_mangle]
pub unsafe extern "C" fn reors_err_buf_destroy(_: Box<ErrBuf>) {}

#[no_mangle]
pub unsafe extern "C" fn reors_proto_destroy(p: ArcProto) {
    drop(Arc::from_raw(p))
}

#[no_mangle]
pub unsafe extern "C" fn reors_putter_destroy(_: Box<Putter>) {}

#[no_mangle]
pub unsafe extern "C" fn reors_getter_destroy(_: Box<Getter>) {}
