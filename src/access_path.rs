use anyhow::Result;
use plonky2::hash::hash_types::MerkleCapTarget;
use plonky2::hash::merkle_proofs::{MerkleProof, MerkleProofTarget};
use plonky2::hash::merkle_tree::{MerkleCap, MerkleTree};
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, VerifierCircuitData};
use plonky2::plonk::config::Hasher;
use plonky2::plonk::proof::ProofWithPublicInputs;

use crate::signal::{Digest, Signal, C, F};

pub struct AccessPath {
    pub merkle_proof: MerkleProof<F, PoseidonHash>,
    pub public_key_index: usize,
    pub merkle_root: MerkleCap<F, PoseidonHash>,
}

impl AccessPath {
    pub fn verify_signal(
        &self,
        topic: Digest,
        signal: Signal,
        verifier_data: &VerifierCircuitData<F, C, 2>,
    ) -> Result<()> {
        let public_inputs: Vec<F> = self
            .merkle_root
            .0
            .iter()
            .flat_map(|h| h.elements)
            .chain(signal.nullifier)
            .chain(topic)
            .collect();

        verifier_data.verify(ProofWithPublicInputs {
            proof: signal.proof,
            public_inputs,
        })
    }

    pub fn make_signal(
        &self,
        private_key: Digest,
        topic: Digest,
        public_key_index: usize,
    ) -> Result<(Signal, VerifierCircuitData<F, C, 2>)> {
        let nullifier = PoseidonHash::hash_no_pad(&[private_key, topic].concat()).elements;
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::new(config);
        let mut pw = PartialWitness::new();

        let targets = self.semaphore_circuit(&mut builder);
        self.fill_semaphore_targets(
            &mut pw,
            private_key,
            topic,
            public_key_index,
            targets,
            self.merkle_root.0[0],
        );

        let data = builder.build();
        let proof = data.prove(pw)?;

        Ok((
            Signal {
                nullifier,
                proof: proof.proof,
            },
            data.to_verifier_data(),
        ))
    }
}
