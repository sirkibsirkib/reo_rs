use super::*;

const BYTES_PER_CHUNK: usize = std::mem::size_of::<usize>();
const BITS_PER_CHUNK: usize = BYTES_PER_CHUNK * 8;

#[derive(Default, Clone)]
pub struct IndexSet {
    // may have zero-word tail
    chunks: SmallVec<[usize; 2]>,
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct Index(pub usize);

struct BitIter<'a> {
    sis: &'a IndexSet,
    cached: usize,
    index_of_next_chunk: usize,
}

#[derive(Debug, Copy, Clone)]
struct BitIndex {
    index_of_chunk: usize,
    index_in_chunk: u32,
}
///////////////////////////////////////////////////////
impl fmt::Debug for Index {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Index({})", self.0)
    }
}
impl BitIndex {
    fn mask(self) -> usize {
        1 << self.index_in_chunk
    }
    fn to_index(self) -> Index {
        Index(self.index_of_chunk * BITS_PER_CHUNK + self.index_in_chunk as usize)
    }
    fn from_index(si: Index) -> Self {
        Self {
            index_of_chunk: si.0 / BITS_PER_CHUNK,
            index_in_chunk: (si.0 % BITS_PER_CHUNK) as u32,
        }
    }
}
impl<'a> Iterator for BitIter<'a> {
    type Item = Index;
    fn next(&mut self) -> Option<Index> {
        while self.cached == 0 {
            self.cached = *self.sis.chunks.get(self.index_of_next_chunk)?;
            self.index_of_next_chunk += 1;
        }
        // self.cached is NONZERO
        let index_in_chunk = self.cached.trailing_zeros();
        self.cached &= !(1 << index_in_chunk);
        let bi = BitIndex { index_in_chunk, index_of_chunk: self.index_of_next_chunk - 1 };
        Some(bi.to_index())
    }
}

impl std::iter::FromIterator<Index> for IndexSet {
    fn from_iter<I: IntoIterator<Item = Index>>(iter: I) -> Self {
        let mut x = Self::default();
        for i in iter {
            x.insert(i);
        }
        x
    }
}
impl IndexSet {
    pub fn len(&self) -> usize {
        self.chunks.iter().map(|chunk| chunk.count_ones() as usize).sum()
    }
    pub fn max_element(&self) -> Option<Index> {
        for (index_of_chunk, chunk) in self.chunks.iter().enumerate().rev() {
            if let Some(index_in_chunk) = (usize::BITS - 1).checked_sub(chunk.leading_zeros()) {
                return Some(BitIndex { index_of_chunk, index_in_chunk }.to_index());
            }
        }
        None
    }
    pub fn with_capacity(space_indices: usize) -> Self {
        let chunk_capacity = space_indices
            .checked_sub(1)
            .map(Index) // largest spaceindex we are making capacity for
            .map(|si| BitIndex::from_index(si).index_of_chunk + 1)
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

    pub fn iter(&self) -> impl Iterator<Item = Index> + '_ {
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

    pub fn insert(&mut self, si: Index) -> bool {
        let bi = BitIndex::from_index(si);
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
    pub fn remove(&mut self, si: &Index) -> bool {
        let bi = BitIndex::from_index(*si);
        if let Some(chunk) = self.chunks.get_mut(bi.index_of_chunk) {
            let was_set = *chunk & bi.mask() != 0;
            *chunk &= !(bi.mask());
            was_set
        } else {
            false
        }
    }
    pub fn contains(&self, si: &Index) -> bool {
        let bi = BitIndex::from_index(*si);
        if let Some(chunk) = self.chunks.get(bi.index_of_chunk) {
            *chunk & bi.mask() != 0
        } else {
            false
        }
    }
}

impl fmt::Debug for IndexSet {
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
