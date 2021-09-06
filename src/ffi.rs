use super::*;

use crate::Proto;

///////////////

pub type ArcProto = *const Proto;

#[no_mangle]
pub unsafe extern "C" fn proto_destroy(p: ArcProto) {
    drop(Arc::from_raw(p))
}

#[no_mangle]
pub unsafe extern "C" fn proto_clone(p: ArcProto) -> ArcProto {
    Arc::into_raw(Arc::from_raw(p))
}

// #[no_mangle]
// pub unsafe extern "C" fn claim_putter(p: ArcProto, name_ptr: ) -> Putter {
// 	let p = Arc::from_raw(p);
// 	Putter::claim_raw(&p, )

//     // Putter::claim_raw()
// }
