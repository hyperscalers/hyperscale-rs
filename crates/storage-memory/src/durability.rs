//! What a store's synced writes made durable, for the machine that
//! loses power.
//!
//! Keeping the image a sync leaves is not free: the live structures and
//! the image share their persistent nodes, so every later write copies
//! the nodes it touches. A store that never loses power tracks nothing.

/// A store's record of its last synced image, if it keeps one.
#[derive(Debug)]
pub enum Durability<T> {
    /// Syncs record nothing; the store cannot lose power.
    Untracked,
    /// The store as its last synced write left it; `None` until a write
    /// syncs.
    Tracked(Option<T>),
}

impl<T> Durability<T> {
    /// A fresh record of the same kind as `self`.
    pub const fn fresh(&self) -> Self {
        match self {
            Self::Untracked => Self::Untracked,
            Self::Tracked(_) => Self::Tracked(None),
        }
    }

    /// Record `image` as durable, if this store tracks durability.
    pub fn sync(&mut self, image: impl FnOnce() -> T) {
        if let Self::Tracked(durable) = self {
            *durable = Some(image());
        }
    }

    /// The last synced image, `None` if no write has synced.
    ///
    /// # Panics
    ///
    /// Panics if the store does not track durability: it has nothing to
    /// roll back to.
    pub fn last_synced(&self) -> Option<&T> {
        match self {
            Self::Untracked => panic!(
                "power lost on a store that does not track durability; open it tracked \
                 to let it lose power"
            ),
            Self::Tracked(durable) => durable.as_ref(),
        }
    }
}
