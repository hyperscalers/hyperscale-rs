//! Where simulated hosts sit, and what that costs a delivery between them.
//!
//! A shard's members are drawn without regard to where their hosts are, so
//! a committee may happen to sit in one region or straddle several, and a
//! leader may sit far from its quorum. Placing hosts in regions makes those
//! seed-driven cases: each host draws a region, and each pair of regions a
//! base latency and a bandwidth, once per run.

use std::time::Duration;

use blake3::Hasher as Blake3Hasher;
use rand::{RngExt, SeedableRng};
use rand_chacha::ChaCha8Rng;

use crate::NodeIndex;

/// How many regions a run spreads its hosts over, and the seed that places
/// them and prices the links between them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegionPlan {
    /// Regions hosts are spread over; at least one.
    pub regions: u8,
    /// Seed for host placement and link prices.
    pub seed: u64,
}

/// What a delivery between two regions costs.
#[derive(Debug, Clone, Copy)]
pub struct Link {
    /// Latency before jitter.
    pub base: Duration,
    /// Bytes the link carries per second.
    pub bytes_per_sec: u64,
}

impl Link {
    /// Time to put `bytes` on the wire.
    pub fn transmission(self, bytes: usize) -> Duration {
        let nanos = u128::try_from(bytes)
            .unwrap_or(u128::MAX)
            .saturating_mul(1_000_000_000)
            / u128::from(self.bytes_per_sec.max(1));
        Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX))
    }
}

/// Hosts placed in regions, and the links between the regions.
#[derive(Debug, Clone)]
pub struct Geography {
    plan: RegionPlan,
    /// `regions × regions`, symmetric.
    links: Vec<Link>,
}

impl Geography {
    /// Price every pair of regions once, symmetrically: a link within a
    /// region is short and wide, one between regions long and narrower.
    pub fn new(plan: RegionPlan) -> Self {
        let regions = usize::from(plan.regions.max(1));
        let mut rng = ChaCha8Rng::from_seed(derive(plan.seed, b"links", 0));
        let mut links = vec![
            Link {
                base: Duration::ZERO,
                bytes_per_sec: 1,
            };
            regions * regions
        ];
        for a in 0..regions {
            for b in a..regions {
                // Real cloud links: a few milliseconds and gigabytes a
                // second within a region; cross-continent one-way delays
                // and the narrower pipes between regions.
                let link = if a == b {
                    Link {
                        base: Duration::from_millis(rng.random_range(1..=10)),
                        bytes_per_sec: rng.random_range(1_000_000_000..=10_000_000_000),
                    }
                } else {
                    Link {
                        base: Duration::from_millis(rng.random_range(40..=160)),
                        bytes_per_sec: rng.random_range(100_000_000..=1_000_000_000),
                    }
                };
                links[a * regions + b] = link;
                links[b * regions + a] = link;
            }
        }
        Self {
            plan: RegionPlan {
                regions: plan.regions.max(1),
                ..plan
            },
            links,
        }
    }

    /// The region `host` sits in, drawn from the plan's seed and the host
    /// alone, so adding a host moves no other.
    pub fn region_of(&self, host: NodeIndex) -> usize {
        let digest = derive(self.plan.seed, b"host", host);
        let draw = u64::from_le_bytes(digest[..8].try_into().expect("eight bytes"));
        usize::try_from(draw % u64::from(self.plan.regions)).expect("a region index")
    }

    /// The link a delivery from `from` to `to` crosses.
    pub fn link(&self, from: NodeIndex, to: NodeIndex) -> Link {
        let regions = usize::from(self.plan.regions);
        self.links[self.region_of(from) * regions + self.region_of(to)]
    }
}

fn derive(seed: u64, label: &[u8], index: NodeIndex) -> [u8; 32] {
    let mut hasher = Blake3Hasher::new();
    hasher.update(&seed.to_le_bytes());
    hasher.update(label);
    hasher.update(&index.to_le_bytes());
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn links_are_symmetric_and_shorter_within_a_region() {
        let geography = Geography::new(RegionPlan {
            regions: 3,
            seed: 7,
        });
        for a in 0..32 {
            for b in 0..32 {
                let (ab, ba) = (geography.link(a, b), geography.link(b, a));
                assert_eq!(ab.base, ba.base);
                assert_eq!(ab.bytes_per_sec, ba.bytes_per_sec);
                if geography.region_of(a) == geography.region_of(b) {
                    assert!(ab.base <= Duration::from_millis(10));
                } else {
                    assert!(ab.base >= Duration::from_millis(40));
                }
            }
        }
    }

    #[test]
    fn a_hosts_region_does_not_depend_on_other_hosts() {
        let geography = Geography::new(RegionPlan {
            regions: 4,
            seed: 11,
        });
        let first: Vec<usize> = (0..8).map(|h| geography.region_of(h)).collect();
        let mut reversed: Vec<usize> = (0..8).rev().map(|h| geography.region_of(h)).collect();
        reversed.reverse();
        assert_eq!(first, reversed);
        let grown = Geography::new(RegionPlan {
            regions: 4,
            seed: 11,
        });
        let wider: Vec<usize> = (0..16).map(|h| grown.region_of(h)).collect();
        assert_eq!(first, wider[..8]);
        assert!(first.iter().all(|&region| region < 4));
    }

    #[test]
    fn transmission_grows_with_bytes() {
        let link = Link {
            base: Duration::ZERO,
            bytes_per_sec: 1_000_000,
        };
        assert_eq!(link.transmission(1_000_000), Duration::from_secs(1));
        assert_eq!(link.transmission(0), Duration::ZERO);
    }
}
