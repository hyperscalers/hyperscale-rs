//! Staking: the graphs a pool's delegators and its operator build.
//!
//! A pool is an instance its network's genesis seats or an account founds
//! (see [`join`](crate::join)), so a client calls a seated pool over a world
//! that seats it, [`Client::with_pools`], and an operator's own founded pool
//! over any world. Delegating is a withdrawal into the pool; registering,
//! retiring and lifting a validator's time-out present the pool's owner
//! badge, which genesis gives a seat's operator and a founding gives its
//! founder.

use std::slice;

use hyperscale_effects_bridge::genesis::{
    GenesisPackages, OWNER_BADGE_ID, founded_pool, genesis_world_with_pools,
    pool_address as seat_address, pool_owner_badge, staking_artifact,
};
use hyperscale_effects_bridge::{PROTOCOL_RESOURCE, ProtocolHasher};
use hyperscale_types::{
    ComponentAddr, ConsensusPublicKey, ConsensusSignature, NetworkId, StakePoolSeat, ValidatorId,
};
use hyperscale_vm_effects::{Composed, ManifestGraph, package_hash};
use hyperscale_vm_manifest_builder::{TypedBuilder, TypedError};
use hyperscale_vm_stdlib::{account, staking};
use hyperscale_vm_types::PrincipalAddr;

use crate::Client;

/// Where a network's genesis seats the pool `seat`.
#[must_use]
pub fn pool_address(seat: &StakePoolSeat) -> ComponentAddr {
    seat_address(package_hash(&ProtocolHasher, staking_artifact()), seat)
}

impl Client {
    /// A client on the world a network seating `pools` starts from, the
    /// protocol's own packages published.
    #[must_use]
    pub fn with_pools(pools: &[StakePoolSeat], network: NetworkId) -> Self {
        Self::new(
            genesis_world_with_pools(pools, &GenesisPackages::protocol()),
            network,
        )
    }

    /// The graph delegating `amount` from `from`'s native balance to
    /// `pool`, composed by `delegator`, banking the stake units the pool
    /// issues back in `from`.
    ///
    /// # Errors
    ///
    /// [`TypedError`] if the account or the pool does not resolve in this
    /// client's world.
    pub fn stake_graph(
        &self,
        delegator: PrincipalAddr,
        from: PrincipalAddr,
        pool: ComponentAddr,
        amount: u128,
    ) -> Result<ManifestGraph, TypedError> {
        let chain = self.records();
        let mut b = self.builder(&chain, delegator);
        let funds = account::withdraw(&mut b, from, *PROTOCOL_RESOURCE, amount)?;
        let units = staking::Staking::at(pool).stake(&mut b, funds)?;
        account::deposit(&mut b, from, units)?;
        b.build()
    }

    /// The graph registering `validator` with `pool`, carrying the consensus
    /// key it will be known by and the proof it holds that key, composed by
    /// `operator`, whose account holds the pool's owner badge.
    ///
    /// # Errors
    ///
    /// [`TypedError`] if the operator's account or the pool does not
    /// resolve in this client's world.
    pub fn register_validator_graph(
        &self,
        operator: PrincipalAddr,
        pool: ComponentAddr,
        validator: ValidatorId,
        key: &ConsensusPublicKey,
        proof: &ConsensusSignature,
    ) -> Result<ManifestGraph, TypedError> {
        self.as_operator(operator, pool, |b| {
            staking::Staking::at(pool).register_validator(
                b,
                validator.inner(),
                *key.as_bytes(),
                *proof.as_bytes(),
            )
        })
    }

    /// The graph retiring `validator` from `pool`, composed by `operator`.
    ///
    /// # Errors
    ///
    /// As [`register_validator_graph`](Self::register_validator_graph).
    pub fn deactivate_validator_graph(
        &self,
        operator: PrincipalAddr,
        pool: ComponentAddr,
        validator: ValidatorId,
    ) -> Result<ManifestGraph, TypedError> {
        self.as_operator(operator, pool, |b| {
            staking::Staking::at(pool).deactivate_validator(b, validator.inner())
        })
    }

    /// The graph lifting `validator`'s time-out in `pool`, composed by
    /// `operator`. The beacon drops a lift it refuses (a cooldown still
    /// running, a full or convicted pool) though the transaction commits,
    /// so a caller reads the validator's status, not the transaction's.
    ///
    /// # Errors
    ///
    /// As [`register_validator_graph`](Self::register_validator_graph).
    pub fn unjail_validator_graph(
        &self,
        operator: PrincipalAddr,
        pool: ComponentAddr,
        validator: ValidatorId,
    ) -> Result<ManifestGraph, TypedError> {
        self.as_operator(operator, pool, |b| {
            staking::Staking::at(pool).unjail(b, validator.inner())
        })
    }

    /// `call` under the pool's owner badge, presented from `operator`'s
    /// account: the whole of an operator action's authority. The
    /// operator's own founded pool is typed whether or not this client's
    /// world holds it, as [`operator_declaration`](Self::operator_declaration)
    /// types it.
    fn as_operator(
        &self,
        operator: PrincipalAddr,
        pool: ComponentAddr,
        call: impl FnOnce(&mut TypedBuilder<'_>) -> Result<(), TypedError>,
    ) -> Result<ManifestGraph, TypedError> {
        let chain = self.records();
        let founded = founded_pool(operator);
        let composed = Composed::new(&chain, slice::from_ref(&founded), &ProtocolHasher);
        let mut b = TypedBuilder::new(&composed, &ProtocolHasher, operator);
        let badge =
            account::present_instance(&mut b, operator, pool_owner_badge(pool), OWNER_BADGE_ID)?;
        b.presenting(badge, call)?;
        b.build()
    }
}

#[cfg(test)]
mod tests {

    use hyperscale_types::test_utils::test_principal;
    use hyperscale_types::{ConsensusPublicKey, ConsensusSignature};

    use super::*;

    const NETWORK: NetworkId = NetworkId(242);

    fn seat(number: u32) -> StakePoolSeat {
        StakePoolSeat {
            number,
            operator: test_principal(7),
            founding: Vec::new(),
        }
    }

    /// Over a world that seats pool 0, its operator's three actions build.
    #[test]
    fn a_seated_pool_takes_a_delegation_a_registration_and_a_retirement() {
        let client = Client::with_pools(&[seat(0)], NETWORK);
        let pool = pool_address(&seat(0));
        let operator = test_principal(7);
        assert!(client.stake_graph(operator, operator, pool, 10).is_ok());
        assert!(
            client
                .register_validator_graph(
                    operator,
                    pool,
                    ValidatorId::new(1000),
                    &ConsensusPublicKey::ZERO,
                    &ConsensusSignature::ZERO,
                )
                .is_ok()
        );
        assert!(
            client
                .deactivate_validator_graph(operator, pool, ValidatorId::new(1000))
                .is_ok()
        );
    }

    /// A founder's own pool is reached over a world that does not seat
    /// it: its retirement and its unjail build alike.
    #[test]
    fn a_founders_own_pool_takes_its_operator_actions() {
        let client = Client::with_pools(&[], NETWORK);
        let founder = test_principal(8);
        let pool = founded_pool(founder).address(&ProtocolHasher);
        assert!(
            client
                .deactivate_validator_graph(founder, pool, ValidatorId::new(1000))
                .is_ok()
        );
        assert!(
            client
                .unjail_validator_graph(founder, pool, ValidatorId::new(1000))
                .is_ok()
        );
    }

    /// A pool the client's world does not seat cannot be called: the
    /// world is what makes an instance reachable.
    #[test]
    fn a_pool_the_world_does_not_seat_does_not_resolve() {
        let client = Client::with_pools(&[seat(0)], NETWORK);
        let elsewhere = pool_address(&seat(9));
        assert!(
            client
                .deactivate_validator_graph(test_principal(7), elsewhere, ValidatorId::new(1))
                .is_err()
        );
    }
}
