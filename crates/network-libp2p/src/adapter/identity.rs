//! Libp2p identity generation.

use libp2p::identity;

/// Generate a random Ed25519 keypair for libp2p transport encryption.
pub fn generate_random_keypair() -> identity::Keypair {
    identity::Keypair::generate_ed25519()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_random_keypair_produces_unique_ids() {
        let kp1 = generate_random_keypair();
        let kp2 = generate_random_keypair();
        assert_ne!(
            kp1.public().to_peer_id(),
            kp2.public().to_peer_id(),
            "Random keypairs should produce different PeerIds"
        );
    }

    #[test]
    fn test_generate_random_keypair_produces_valid_peer_id() {
        let kp = generate_random_keypair();
        let peer_id = kp.public().to_peer_id();
        assert!(!peer_id.to_string().is_empty());
    }
}
