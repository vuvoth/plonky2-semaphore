use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::plonk::proof::Proof;

pub type F = GoldilocksField;
pub type Digest = [F; 4];
pub type C = PoseidonGoldilocksConfig;
pub type PlonkyProof = Proof<F, PoseidonGoldilocksConfig, 2>;

#[derive(Debug, Clone)]
pub struct Signal {
    pub nullifier: Digest,
    pub proof: PlonkyProof,
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::prelude::*;

    use anyhow::Result;
    use plonky2::field::field_types::Field;
    use plonky2::hash::merkle_tree::MerkleTree;
    use plonky2::hash::poseidon::PoseidonHash;
    use plonky2::plonk::circuit_data::VerifierCircuitData;
    use plonky2::plonk::config::Hasher;
    use plonky2_circom_verifier::verifier::generate_verifier_config;
    use serde_json::json;

    use crate::access_path::AccessPath;
    use crate::signal::{Digest, C, F};

    #[test]
    fn test_semaphore() -> Result<()> {
        let n = 1 << 5;
        let private_keys: Vec<Digest> = (0..n).map(|_| F::rand_arr()).collect();
        let public_keys: Vec<Vec<F>> = private_keys
            .iter()
            .map(|&sk| {
                PoseidonHash::hash_no_pad(&[sk, [F::ZERO; 4]].concat())
                    .elements
                    .to_vec()
            })
            .collect();
        let merkle_tree = MerkleTree::new(public_keys, 0);

        let leaf_index = 12;

        let access_path = AccessPath {
            merkle_proof: merkle_tree.prove(leaf_index),
            public_key_index: leaf_index,
            merkle_root: merkle_tree.cap.clone(),
        };

        let topic = F::rand_arr();

        let (signal, vd) = access_path.make_signal(private_keys[leaf_index], topic, leaf_index)?;
        access_path.verify_signal(topic, signal, &vd);

        //
        let leaf_0 = 10;
        let leaf_1 = 14;
        let access_path_0 = AccessPath {
            merkle_proof: merkle_tree.prove(leaf_0),
            public_key_index: leaf_0,
            merkle_root: merkle_tree.cap.clone(),
        };

        let access_path_1 = AccessPath {
            merkle_proof: merkle_tree.prove(leaf_1),
            public_key_index: leaf_1,
            merkle_root: merkle_tree.cap.clone(),
        };

        let (signal_0, vd_0) = access_path_0.make_signal(private_keys[leaf_0], topic, leaf_0)?;
        let (signal_1, vd_1) = access_path_1.make_signal(private_keys[leaf_1], topic, leaf_1)?;

        // let vdr: VerifierCircuitData<F, C, 2>;
        let (_, _, p) = access_path.aggregate_signals(topic, signal_0, topic, signal_1, &vd_0, &vd_1);

        
        
        let data = json!(p);
        
        let mut buffer = File::create("proof.json")?;

        buffer.write_all(data.to_string().as_bytes());
        
        Ok(())
    }
}
