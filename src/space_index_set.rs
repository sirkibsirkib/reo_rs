use super::*;

const BYTES_PER_CHUNK: usize = std::mem::size_of::<usize>();
const BITS_PER_CHUNK: usize = BYTES_PER_CHUNK * 8;

#[derive(Default, Clone)]
pub(crate) struct SpaceIndexSet {
    // may have zero-word tail
    pub(crate) chunks: SmallVec<[usize; 3]>,
}
struct BitIter<'a> {
    sis: &'a SpaceIndexSet,
    cached: usize,
    index_of_next_chunk: usize,
}

#[derive(Debug, Copy, Clone)]
struct BitIndex {
    index_of_chunk: usize,
    index_in_chunk: u32,
}
///////////////////////////////////////////////////////
impl BitIndex {
    fn mask(self) -> usize {
        1 << self.index_in_chunk
    }
    fn to_space_index(self) -> SpaceIndex {
        SpaceIndex(self.index_of_chunk * BITS_PER_CHUNK + self.index_in_chunk as usize)
    }
    fn from_space_index(si: SpaceIndex) -> Self {
        Self {
            index_of_chunk: si.0 / BITS_PER_CHUNK,
            index_in_chunk: (si.0 % BITS_PER_CHUNK) as u32,
        }
    }
}
impl<'a> Iterator for BitIter<'a> {
    type Item = SpaceIndex;
    fn next(&mut self) -> Option<SpaceIndex> {
        while self.cached == 0 {
            self.cached = *self.sis.chunks.get(self.index_of_next_chunk)?;
            self.index_of_next_chunk += 1;
        }
        // self.cached is NONZERO
        let index_in_chunk = self.cached.trailing_zeros();
        self.cached &= !(1 << index_in_chunk);
        let bi = BitIndex { index_in_chunk, index_of_chunk: self.index_of_next_chunk - 1 };
        Some(bi.to_space_index())
    }
}

impl std::iter::FromIterator<SpaceIndex> for SpaceIndexSet {
    fn from_iter<I: IntoIterator<Item = SpaceIndex>>(iter: I) -> Self {
        let mut x = Self::default();
        for i in iter {
            x.insert(i);
        }
        x
    }
}
impl SpaceIndexSet {
    pub fn with_capacity(space_indices: usize) -> Self {
        let chunk_capacity = space_indices
            .checked_sub(1)
            .map(SpaceIndex) // largest spaceindex we are making capacity for
            .map(|si| BitIndex::from_space_index(si).index_of_chunk + 1)
            .unwrap_or(0);
        Self { chunks: SmallVec::with_capacity(chunk_capacity) }
    }
    pub fn remove_all(&mut self, other: &Self) {
        // assumes lengths are sufficient
        for (a, b) in self.chunks.iter_mut().zip(other.chunks.iter()) {
            *a &= !*b;
        }
    }
    pub fn insert_all(&mut self, other: &Self) {
        while self.chunks.len() < other.chunks.len() {
            self.chunks.push(0)
        }
        for (a, b) in self.chunks.iter_mut().zip(other.chunks.iter()) {
            *a |= *b;
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = SpaceIndex> + '_ {
        BitIter { sis: self, index_of_next_chunk: 0, cached: 0 }
    }
    pub fn is_disjoint_with(&self, other: &Self) -> bool {
        for (&a, &b) in self.chunks.iter().zip(other.chunks.iter()) {
            if a & b != 0 {
                return false;
            }
        }
        true
    }
    pub fn is_subset_of(&self, other: &Self) -> bool {
        for (&a, &b) in self.chunks.iter().zip(other.chunks.iter()) {
            if a & !b != 0 {
                return false;
            }
        }
        true
    }

    pub fn insert(&mut self, si: SpaceIndex) -> bool {
        let bi = BitIndex::from_space_index(si);
        while self.chunks.len() <= bi.index_of_chunk {
            self.chunks.push(0);
        }
        // self.chunks.len() > bi.index_of_chunk
        let chunk = unsafe {
            // safe! read will not go out of bounds
            self.chunks.get_unchecked_mut(bi.index_of_chunk)
        };
        let was_set = *chunk & bi.mask() != 0;
        *chunk |= bi.mask();
        !was_set
    }
    pub fn remove(&mut self, si: &SpaceIndex) -> bool {
        let bi = BitIndex::from_space_index(*si);
        if let Some(chunk) = self.chunks.get_mut(bi.index_of_chunk) {
            let was_set = *chunk & bi.mask() != 0;
            *chunk &= !(bi.mask());
            was_set
        } else {
            false
        }
    }
    pub fn contains(&self, si: &SpaceIndex) -> bool {
        let bi = BitIndex::from_space_index(*si);
        if let Some(chunk) = self.chunks.get(bi.index_of_chunk) {
            *chunk & bi.mask() != 0
        } else {
            false
        }
    }
}

impl fmt::Debug for SpaceIndexSet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[")?;
        for b in self.chunks.iter().rev().take(1) {
            write!(f, "{:b}", b)?;
        }
        for b in self.chunks.iter().rev().skip(1) {
            write!(f, ".{:b}", b)?;
        }
        write!(f, "]")
    }
}
