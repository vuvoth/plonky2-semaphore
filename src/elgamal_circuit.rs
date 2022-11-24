use plonky2::{iop::target::Target, plonk::circuit_builder::CircuitBuilder};

use crate::signal::F;

/**
 * Prove plain text awareness of an elgamal ciphertext
 */

pub struct ElgamalCircuit {
    pub sk: [F; 4],
    pub pk: [F; 4],
    pub m: [F; 4],
    pub r: [F; 4],
    pub g: [F; 4],
    pub q: [F; 4],
    pub c: [F; 4],
}

impl ElgamalCircuit {
    pub fn elgamal_circuit(&self, builder: &mut CircuitBuilder<F, 2>) {
        // let sk: [Target; 4] = builder.add_virtual_targets(4).try_into().unwrap();
        // let pk: [Target; 4] = builder.add_virtual_targets(4).try_into().unwrap();
        // let m: [Target; 4] = builder.add_virtual_targets(4).try_into().unwrap();
        // let r: [Target; 4] = builder.add_virtual_targets(4).try_into().unwrap();
        // let g: [Target; 4] = builder.add_virtual_targets(4).try_into().unwrap();
        // let q: [Target; 4] = builder.add_virtual_targets(4).try_into().unwrap();
        // let c: [Target; 4] = builder.add_virtual_targets(4).try_into().unwrap();

        // builder.register_public_inputs(&pk);
        // builder.register_public_inputs(&m);
        // builder.register_public_inputs(&g);
        // builder.register_public_inputs(&q);
        // builder.register_public_inputs(&c);

        // builder.exp(base, exponent, num_bits)

    // * by default q = prime of the field F
        let sk = builder.add_virtual_target();
        let m = builder.add_virtual_target();
        let r = builder.add_virtual_target();
        let g = builder.add_virtual_target();

        let num_bits = 32;
        let pk = builder.exp(g, sk, num_bits);
        let c_0 = builder.exp(g, r, num_bits);
        let s = builder.exp(pk, r, num_bits);
        let c_1 = builder.mul(m, s);

        builder.register_public_input(pk);
        builder.register_public_input(m);
        builder.register_public_input(g);
        builder.register_public_input(c_0);
        builder.register_public_input(c_1);
    }
    pub fn fill_circuit(&self) {}
}
