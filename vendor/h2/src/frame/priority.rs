use crate::frame::*;
use bytes::BufMut;

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct Priority {
    stream_id: StreamId,
    dependency: StreamDependency,
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct StreamDependency {
    /// The ID of the stream dependency target
    dependency_id: StreamId,

    /// The weight for the stream. The value exposed (and set) here is always in
    /// the range [0, 255], instead of [1, 256] (as defined in section 5.3.2.)
    /// so that the value fits into a `u8`.
    weight: u8,

    /// True if the stream dependency is exclusive.
    is_exclusive: bool,
}

impl Priority {
    pub fn new(stream_id: StreamId, dependency: StreamDependency) -> Self {
        Priority { stream_id, dependency }
    }

    pub fn load(head: Head, payload: &[u8]) -> Result<Self, Error> {
        let dependency = StreamDependency::load(payload)?;

        if dependency.dependency_id() == head.stream_id() {
            return Err(Error::InvalidDependencyId);
        }

        Ok(Priority {
            stream_id: head.stream_id(),
            dependency,
        })
    }

    pub fn encode(&self, dst: &mut impl BufMut) {
        let head = Head::new(Kind::Priority, 0, self.stream_id);
        head.encode(5, dst);
        self.dependency.encode(dst);
    }
}

impl<B> From<Priority> for Frame<B> {
    fn from(src: Priority) -> Self {
        Frame::Priority(src)
    }
}

// ===== impl StreamDependency =====

impl StreamDependency {
    pub fn new(dependency_id: StreamId, weight: u8, is_exclusive: bool) -> Self {
        StreamDependency {
            dependency_id,
            weight,
            is_exclusive,
        }
    }

    pub fn load(src: &[u8]) -> Result<Self, Error> {
        if src.len() != 5 {
            return Err(Error::InvalidPayloadLength);
        }

        // Parse the stream ID and exclusive flag
        let (dependency_id, is_exclusive) = StreamId::parse(&src[..4]);

        // Read the weight
        let weight = src[4];

        Ok(StreamDependency::new(dependency_id, weight, is_exclusive))
    }

    pub fn dependency_id(&self) -> StreamId {
        self.dependency_id
    }

    pub fn weight(&self) -> u8 {
        self.weight
    }

    pub fn is_exclusive(&self) -> bool {
        self.is_exclusive
    }

    pub fn encode(&self, dst: &mut impl BufMut) {
        let mut dep_id = u32::from(self.dependency_id);
        if self.is_exclusive {
            dep_id |= 0x8000_0000;
        }
        dst.put_u32(dep_id);
        dst.put_u8(self.weight);
    }
}
