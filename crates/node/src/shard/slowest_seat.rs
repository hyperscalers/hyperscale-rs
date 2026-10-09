//! The syncs a loop shares among its seats follow the slowest seat.
//!
//! A loop carries every seat it hosts of one shard, and each seat verifies,
//! applies and commits on its own, so seats sit at different heights: a
//! joiner restores at the store's committed tip below siblings holding
//! synced blocks above it, and a seat seated next to a sibling at a remote
//! shard's tip starts from its own attested boundary. One sync serves them
//! all, so what it fetches or counts done derives from the lowest position
//! any seat holds, never from how far a caught-up sibling got. A seat
//! holding less than a sync counts rewinds it, and the heights it lacks are
//! fetched again rather than dropped as done.

use std::collections::BTreeMap;

use hyperscale_dispatch::Dispatch;
use hyperscale_network::Network;
use hyperscale_storage::ShardStorage;
use hyperscale_types::{BlockHeight, ShardId, ValidatorId};

use crate::shard::ShardLoop;
use crate::shard::consensus::BlockSyncInput;
use crate::shard::cross_shard::RemoteHeaderSyncInput;

impl<S, N, D> ShardLoop<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    /// Point every sync the loop shares at the slowest seat.
    pub(super) fn follow_slowest_seat(&mut self) {
        self.follow_slowest_block_sync_seat();
        self.follow_slowest_remote_header_seats();
    }

    /// Each seat's own committed height, as far as the loop's commit
    /// pipeline has taken it: a coordinator counts a QC-only commit before
    /// its prep returns, and the sync's commit frontier is the pipeline's.
    /// No block below a chain's origin exists anywhere, so a seat whose
    /// coordinator has yet to fold its chain's first block holds
    /// everything there is below it.
    fn seat_committed_heights(&self) -> Vec<(ValidatorId, BlockHeight)> {
        let accepted = self.io.block_commit.accepted_height();
        self.vnodes
            .iter()
            .map(|vnode| {
                let coordinator = vnode.state.shard_coordinator();
                let committed = coordinator
                    .committed_height()
                    .min(accepted)
                    .max(coordinator.chain_origin().genesis_height);
                (vnode.validator_id, committed)
            })
            .collect()
    }

    /// Point the block sync at the slowest seat: it counts admitted the
    /// height every seat has committed, and held the height every seat
    /// holds, applied or committed.
    pub(crate) fn follow_slowest_block_sync_seat(&mut self) {
        let seats = self.seat_committed_heights();
        let Some(committed) = seats.iter().map(|&(_, committed)| committed).min() else {
            return;
        };
        let held = self
            .io
            .consensus
            .seat_frontiers
            .held(seats)
            .expect("a loop with seats holds a height");
        let sync = &mut self.io.consensus.block_sync;
        let mut outputs = Vec::new();
        if sync
            .committed(&())
            .is_none_or(|admitted| committed > admitted)
        {
            outputs.extend(sync.handle(BlockSyncInput::Admitted {
                scope: (),
                height: committed,
            }));
        }
        let frontier = sync.frontier(&()).unwrap_or(committed);
        if held < frontier {
            outputs.extend(sync.handle(BlockSyncInput::Rewind {
                scope: (),
                height: held,
            }));
        } else if held > frontier {
            outputs.extend(sync.handle(BlockSyncInput::Applied {
                scope: (),
                height: held,
            }));
        }
        self.process_block_sync_outputs(outputs);
    }

    /// Point every remote shard's scope at the slowest seat tracking it.
    fn follow_slowest_remote_header_seats(&mut self) {
        let mut slowest: BTreeMap<ShardId, BlockHeight> = BTreeMap::new();
        for vnode in &self.vnodes {
            for (shard, frontier) in vnode
                .state
                .remote_headers_coordinator()
                .verified_frontiers()
            {
                slowest
                    .entry(shard)
                    .and_modify(|lowest| *lowest = (*lowest).min(frontier))
                    .or_insert(frontier);
            }
        }
        for (source_shard, frontier) in slowest {
            self.move_remote_header_scope(source_shard, frontier);
        }
    }

    /// Point `source_shard`'s scope at the slowest seat tracking it: the
    /// lowest verified frontier any seat holds. Seats not tracking the
    /// shard have no say.
    pub(crate) fn follow_slowest_remote_header_seat(&mut self, source_shard: ShardId) {
        let slowest = self
            .vnodes
            .iter()
            .filter_map(|vnode| {
                vnode
                    .state
                    .remote_headers_coordinator()
                    .verified_frontier(source_shard)
            })
            .min();
        if let Some(frontier) = slowest {
            self.move_remote_header_scope(source_shard, frontier);
        }
    }

    /// Admit `source_shard`'s scope up to `frontier`, or rewind it there.
    fn move_remote_header_scope(&mut self, source_shard: ShardId, frontier: BlockHeight) {
        let sync = &mut self.io.cross_shard.remote_header_sync;
        let input = match sync.frontier(&source_shard) {
            Some(held) if frontier == held => return,
            Some(held) if frontier < held => RemoteHeaderSyncInput::Rewind {
                scope: source_shard,
                height: frontier,
            },
            _ => RemoteHeaderSyncInput::Admitted {
                scope: source_shard,
                height: frontier,
            },
        };
        let outputs = sync.handle(input);
        self.process_remote_header_sync_outputs(outputs);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use arc_swap::ArcSwap;
    use crossbeam::channel::unbounded;
    use hyperscale_beacon::coordinator::{BeaconCoordinator, LocalChainAnchors};
    use hyperscale_beacon::genesis::build_genesis_beacon_state;
    use hyperscale_core::ProtocolEvent;
    use hyperscale_crypto_bls::BlsVerifier;
    use hyperscale_dispatch_sync::SyncDispatch;
    use hyperscale_engine::{AllCodeRuns, ExecutionMode, Executor};
    use hyperscale_execution::{CrossingIndexSlot, ExecCertStore, FinalizationStore};
    use hyperscale_mempool::{MempoolConfig, TxStore};
    use hyperscale_network::HandlerRegistry;
    use hyperscale_network_memory::SimNetworkAdapter;
    use hyperscale_provisions::{ProvisionConfig, ProvisionStore};
    use hyperscale_shard::ShardConsensusConfig;
    use hyperscale_storage::{BeaconStorage, RecoveredState};
    use hyperscale_storage_memory::{SimBeaconStorage, SimShardStorage};
    use hyperscale_types::test_utils::{StubVmStatics, TestCommittee};
    use hyperscale_types::{
        AggregateSignature, BeaconChainConfig, BeaconGenesisConfig, BeaconState, BlockHash,
        BlockHeader, BlockHeaderParts, BlockHeight, CertifiedBeaconBlock, CertifiedBlockHeader,
        GenesisConfigHash, GenesisPool, GenesisValidator, Hash, HeaderFetchCount, MIN_STAKE_FLOOR,
        NetworkDefinition, ProposerTimestamp, QuorumCertificate, Randomness, Round, ShardId,
        SignerBitfield, Stake, StakePoolId, TopologySnapshot, ValidatorId, ValidatorInfo,
        ValidatorSet, Verified, WeightedTimestamp, genesis_config_hash, shard_prefix_path,
    };

    use crate::shard::ShardLoop;
    use crate::{NodeConfig, NodeHost, NodeStateMachine, SeatConfig, VnodeInit, VnodeSeat};

    const SHARD: ShardId = ShardId::leaf(1, 0);

    type Host = NodeHost<SimShardStorage, SimNetworkAdapter, SyncDispatch>;
    type Loop = ShardLoop<SimShardStorage, SimNetworkAdapter, SyncDispatch>;

    /// A one-pool genesis whose first two validators seat on `SHARD`.
    struct Fixture {
        committee: TestCommittee,
        genesis_block: Arc<Verified<CertifiedBeaconBlock>>,
        genesis_state: BeaconState,
        config_hash: GenesisConfigHash,
        topology_snapshot: Arc<TopologySnapshot>,
    }

    impl Fixture {
        fn new() -> Self {
            let committee = TestCommittee::new(4, 7);
            let network = NetworkDefinition::simulator();
            let pool = StakePoolId::new(0);
            let ids: Vec<ValidatorId> = (0..4).map(|i| committee.validator_id(i)).collect();
            let config = BeaconGenesisConfig {
                chain_config: BeaconChainConfig::default(),
                initial_validators: (0..4)
                    .map(|i| GenesisValidator {
                        id: committee.validator_id(i),
                        pool,
                        pubkey: *committee.public_key(i),
                    })
                    .collect(),
                initial_pools: vec![GenesisPool {
                    id: pool,
                    total_stake: Stake::from_quanta(4 * MIN_STAKE_FLOOR.quanta()),
                }],
                initial_beacon_committee: ids.clone(),
                initial_shard_committee: ids,
                initial_randomness: Randomness::new([0x42; 32]),
            };
            let genesis_state = build_genesis_beacon_state(&config);
            let config_hash = genesis_config_hash(&config, &network, &[]);
            let genesis_block = Arc::new(Verified::<CertifiedBeaconBlock>::genesis(config_hash));
            let validator_set = ValidatorSet::new(
                (0..4)
                    .map(|i| ValidatorInfo {
                        validator_id: committee.validator_id(i),
                        public_key: *committee.public_key(i),
                    })
                    .collect(),
            );
            let shard_committees = BTreeMap::from([(
                SHARD,
                vec![committee.validator_id(0), committee.validator_id(1)],
            )]);
            let topology_snapshot = Arc::new(TopologySnapshot::with_shard_committees(
                network,
                2,
                &validator_set,
                shard_committees,
            ));
            Self {
                committee,
                genesis_block,
                genesis_state,
                config_hash,
                topology_snapshot,
            }
        }

        /// A vnode for `committee[idx]` on `SHARD`, restored at `recovered`.
        fn vnode_init(&self, idx: usize, recovered: &RecoveredState) -> VnodeInit {
            let me = self.committee.validator_id(idx);
            let beacon = BeaconCoordinator::new(
                Arc::new(BlsVerifier),
                Arc::clone(&self.genesis_block),
                vec![self.genesis_state.clone()],
                me,
                SHARD,
                Some(LocalChainAnchors::GENESIS),
                NetworkDefinition::simulator(),
                self.config_hash,
            );
            let state = NodeStateMachine::new(
                me,
                Arc::new(StubVmStatics),
                Arc::new(AllCodeRuns),
                SHARD,
                &ShardConsensusConfig::default(),
                recovered,
                beacon,
                MempoolConfig::default(),
                ProvisionConfig::default(),
                Arc::new(ProvisionStore::new()),
                Arc::new(TxStore::new()),
                Arc::new(ExecCertStore::new()),
                Arc::new(FinalizationStore::new()),
                Arc::new(CrossingIndexSlot::default()),
            );
            VnodeInit {
                state,
                signer: self.committee.signer(idx),
            }
        }

        /// A queued seat for `committee[idx]`.
        fn seat(&self, idx: usize) -> VnodeSeat {
            VnodeSeat {
                config: SeatConfig {
                    verifier: Arc::new(BlsVerifier),
                    derivation: Arc::new(StubVmStatics),
                    code: Arc::new(AllCodeRuns),
                    beacon_network: NetworkDefinition::simulator(),
                    beacon_config_hash: self.config_hash,
                    shard_config: ShardConsensusConfig::default(),
                    mempool_config: MempoolConfig::default(),
                    provision_config: ProvisionConfig::default(),
                },
                validator: self.committee.validator_id(idx),
                signer: self.committee.signer(idx),
            }
        }

        /// A host running `SHARD` with `committee[0]` seated, restored at
        /// `committed` over an empty store.
        fn host(&self, committed: BlockHeight) -> Host {
            let registry = Arc::new(HandlerRegistry::new(std::iter::once(SHARD).collect()));
            let (event_tx, _event_rx) = unbounded();
            let beacon_storage: Arc<dyn BeaconStorage> = Arc::new(SimBeaconStorage::new());
            beacon_storage
                .commit_beacon_block(&self.genesis_block, &Arc::new(self.genesis_state.clone()));
            let recovered = RecoveredState {
                committed_height: committed,
                ..RecoveredState::default()
            };
            NodeHost::new(
                vec![self.vnode_init(0, &recovered)],
                std::iter::once((SHARD, SimShardStorage::new(shard_prefix_path(SHARD)))).collect(),
                beacon_storage,
                NetworkDefinition::simulator(),
                Arc::new(Executor::new(ExecutionMode::Serial)),
                SimNetworkAdapter::new(registry),
                SyncDispatch::new(),
                std::iter::once((SHARD, event_tx.clone())).collect(),
                event_tx,
                Arc::new(ArcSwap::from(Arc::clone(&self.topology_snapshot))),
                NodeConfig::default(),
            )
        }
    }

    /// Requests the loop has sent toward `shard` since the last call.
    fn requests_to(host: &Host, shard: ShardId) -> usize {
        host.network()
            .drain_pending_requests()
            .iter()
            .filter(|request| request.shard == shard)
            .count()
    }

    /// A certified header of `shard` at `height` extending `parent`.
    fn remote_header(
        shard: ShardId,
        height: u64,
        parent: Option<&Arc<Verified<CertifiedBlockHeader>>>,
    ) -> Arc<Verified<CertifiedBlockHeader>> {
        let parent_hash = parent.map_or_else(
            || BlockHash::from_raw(Hash::from_bytes(&height.to_le_bytes())),
            |p| p.block_hash(),
        );
        let parent_qc = QuorumCertificate::new(
            parent_hash,
            shard,
            BlockHeight::new(height.saturating_sub(1)),
            BlockHash::ZERO,
            Round::new(height.saturating_sub(1)),
            SignerBitfield::empty(),
            AggregateSignature::ZERO,
            WeightedTimestamp::from_millis(height * 1_000),
        );
        let header = BlockHeader::new(BlockHeaderParts {
            shard_id: shard,
            height: BlockHeight::new(height),
            parent_block_hash: parent_hash,
            parent_qc: parent_qc.into(),
            timestamp: ProposerTimestamp::from_millis(0),
            round: Round::new(height),
            ..Default::default()
        });
        let qc = QuorumCertificate::new(
            header.hash(),
            shard,
            BlockHeight::new(height),
            parent_hash,
            Round::new(height),
            SignerBitfield::empty(),
            AggregateSignature::ZERO,
            WeightedTimestamp::from_millis(height * 1_000),
        );
        Arc::new(Verified::new_unchecked_for_test(CertifiedBlockHeader::new(
            header, qc,
        )))
    }

    fn loop_of(host: &mut Host) -> &mut Loop {
        host.shard_loop_mut(SHARD)
    }

    /// A seat joining below a sibling's committed tip pulls the block sync
    /// down to its own height, and a sync toward the tip fetches every
    /// height the joiner lacks, not only those above the sibling.
    #[test]
    fn a_joiner_below_its_sibling_syncs_its_whole_gap() {
        let fix = Fixture::new();
        let mut host = fix.host(BlockHeight::new(10));
        loop_of(&mut host).follow_slowest_seat();
        assert_eq!(
            loop_of(&mut host).io.consensus.block_sync.frontier(&()),
            Some(BlockHeight::new(10)),
            "a lone seat holds its own restored tip",
        );

        let out = host.seat_vnode(SHARD, fix.seat(1));
        assert_eq!(out.seated, vec![fix.committee.validator_id(1)]);
        let _ = requests_to(&host, SHARD);

        let shard_loop = loop_of(&mut host);
        assert_eq!(
            shard_loop.io.consensus.block_sync.frontier(&()),
            Some(BlockHeight::GENESIS),
            "the sync counts from the joiner, not the sibling",
        );
        shard_loop.process_start_block_sync(BlockHeight::new(12));
        let status = shard_loop.io.consensus.block_sync.status(&());
        assert_eq!(
            status.pending_fetches, 12,
            "heights 1 through 12 are fetched"
        );
        assert_eq!(requests_to(&host, SHARD), 12);
    }

    /// A seat whose remote-header frontier trails a sibling's still has its
    /// gap fetched: the source shard's scope sits at the lagging seat's
    /// frontier, and its sync request reaches below the sibling's.
    #[test]
    fn a_seat_behind_its_sibling_on_a_remote_shard_fetches_its_gap() {
        let fix = Fixture::new();
        let mut host = fix.host(BlockHeight::GENESIS);
        let _ = host.seat_vnode(SHARD, fix.seat(1));
        let leader = fix.committee.validator_id(0);

        // Every seat starts tracking the shards its schedule routes to.
        let shard_loop = loop_of(&mut host);
        shard_loop.dispatch_event(ProtocolEvent::BlockSyncComplete {
            height: BlockHeight::GENESIS,
        });
        let remote = shard_loop.vnodes[0]
            .state
            .remote_headers_coordinator()
            .verified_frontiers()
            .map(|(shard, _)| shard)
            .next()
            .expect("the schedule routes to a remote shard");

        // Only the first seat hears the source's first five headers.
        let mut parent = None;
        for height in 1..=5 {
            let header = remote_header(remote, height, parent.as_ref());
            shard_loop.dispatch_to_seat(
                leader,
                ProtocolEvent::VerifiedRemoteHeaderReceived {
                    certified_header: Arc::clone(&header),
                    sender: leader,
                },
            );
            parent = Some(header);
        }
        let frontiers: Vec<Option<BlockHeight>> = shard_loop
            .vnodes
            .iter()
            .map(|v| {
                v.state
                    .remote_headers_coordinator()
                    .verified_frontier(remote)
            })
            .collect();
        assert_eq!(
            frontiers,
            vec![Some(BlockHeight::new(5)), Some(BlockHeight::GENESIS)],
        );
        assert_eq!(
            shard_loop
                .io
                .cross_shard
                .remote_header_sync
                .frontier(&remote),
            Some(BlockHeight::GENESIS),
            "the scope sits at the lagging seat's frontier",
        );
        // The probe the tracking started finds the source holding nothing
        // the scope lacks, and the scope settles where it stands.
        let probed = shard_loop
            .io
            .cross_shard
            .remote_header_sync
            .status(&remote)
            .target_height;
        shard_loop.handle_remote_headers_response_received(
            remote,
            BlockHeight::new(1),
            HeaderFetchCount::new(probed),
            Vec::new(),
            None,
        );
        let _ = requests_to(&host, remote);

        // The lagging seat asks for the headers its sibling already holds.
        let shard_loop = loop_of(&mut host);
        shard_loop.process_start_remote_header_sync(remote, BlockHeight::new(5));
        let status = shard_loop.io.cross_shard.remote_header_sync.status(&remote);
        assert_eq!(
            (status.blocks_behind, status.pending_fetches),
            (5, 1),
            "heights 1 through 5 go out in one range",
        );
        assert_eq!(requests_to(&host, remote), 1);
    }
}
