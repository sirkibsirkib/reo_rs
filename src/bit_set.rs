use super::*;

pub trait SetExt {
    fn set_sub(&mut self, other: &Self);
    fn set_add(&mut self, other: &Self);
}
impl SetExt for HashSet<LocId> {
    fn set_sub(&mut self, other: &Self) {
        for q in other.iter() {
            self.remove(q);
        }
    }
    fn set_add(&mut self, other: &Self) {
        for &q in other.iter() {
            self.insert(q);
        }
    }
}

#[derive(Default, Clone)]
pub struct BitSet {
    pub(crate) data: SmallVec<[usize;4]>,
}
impl SetExt for BitSet {
    fn set_sub(&mut self, other: &Self) {
        // assumes lengths are sufficient
        // assert_eq!(self.data.len(), other.data.len());
        for (a, b) in self.data.iter_mut().zip(other.data.iter()) {
            *a &= ! *b;
        }
    }
    fn set_add(&mut self, other: &Self) {
        // assumes lengths are sufficient
        // assert_eq!(self.data.len(), other.data.len());
        for (a, b) in self.data.iter_mut().zip(other.data.iter()) {
            *a |= *b;
        }
    }
}
impl std::iter::FromIterator<LocId> for BitSet {
    fn from_iter<I: IntoIterator<Item=LocId>>(iter: I) -> Self {
        let mut x = Self::default();
        for i in iter {
            x.insert(i);
        }
        x
    }
} 
pub struct BitIter<'a> {
    // counts from n down to 0
    // n is the element we just checked
    n: LocId,
    b: &'a BitSet,
}
impl<'a> Iterator for BitIter<'a> {
    type Item = LocId;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.n.0 == 0 {
                return None
            }
            self.n.0 -= 1;
            let got = self.b.contains(&self.n);
            if got {
                return Some(self.n)
            }
        }
    }
}
impl BitSet {
    const BYTES_PER_CHUNK: usize = std::mem::size_of::<usize>();
    const BITS_PER_CHUNK: usize = Self::BYTES_PER_CHUNK * 8;

    pub fn iter(&self) -> impl Iterator<Item=LocId> + '_ {
        let n = LocId(self.data.len() * Self::BITS_PER_CHUNK + 1);
        BitIter {n, b:self}
    }
    pub fn is_disjoint(&self, other: &Self) -> bool {
        for (&a, &b) in self.data.iter().zip(other.data.iter()) {
            if a&b != 0 {
                return false
            }
        }
        true
    }
    pub fn is_subset(&self, other: &Self) -> bool {
        for (&a, &b) in self.data.iter().zip(other.data.iter()) {
            if a & !b != 0 {
                return false
            }
        }
        true
    }
    pub fn pad_to_cap(&mut self, cap: usize) {
        let chunk_idx = (cap+1) / Self::BITS_PER_CHUNK;
        while self.data.len() <= chunk_idx {
            self.data.push(0);
        }
    }

    pub fn insert(&mut self, val: LocId) -> bool {
        let mask = 1 << (val.0 % Self::BITS_PER_CHUNK);
        let chunk_idx = val.0 / Self::BITS_PER_CHUNK;
        let chunk: &mut usize = match self.data.get_mut(chunk_idx) {
            None => {
                while self.data.len() <= chunk_idx {
                    self.data.push(0);
                }
                &mut self.data[chunk_idx]
            }
            Some(c) => c,
        };
        let wasnt_set: bool = (*chunk & mask) == 0;
        *chunk |= mask;
        wasnt_set
    }
    pub fn remove(&mut self, val: &LocId) -> bool {
        let mask = 1 << (val.0 % Self::BITS_PER_CHUNK);
        let chunk_idx = val.0 / Self::BITS_PER_CHUNK;
        let chunk = match self.data.get_mut(chunk_idx) {
            None => return false,
            Some(c) => c,
        };
        let was_set: bool = (*chunk & mask) != 0;
        *chunk &= !mask;
        was_set
    }
    pub fn contains(&self, idx: &LocId) -> bool {
        let mask = 1 << (idx.0 % Self::BITS_PER_CHUNK);
        let chunk_idx = idx.0 / Self::BITS_PER_CHUNK;
        match self.data.get(chunk_idx) {
            Some(chunk) => chunk & mask != 0,
            None => false,
        }
    }

}

impl fmt::Debug for BitSet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[")?;
        for b in self.data.iter().rev().take(1) {
            write!(f, "{:b}", b)?;
        }
        for b in self.data.iter().rev().skip(1) {
            write!(f, ".{:b}", b)?;
        }
        write!(f, "]")
    }
}