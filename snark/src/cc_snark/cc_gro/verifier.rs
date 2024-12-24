use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};

use crate::cc_snark::cc_gro::{r1cs_to_qap::R1CSToQAP, CcGroth16};
use crate::registerdata::DATA_SET;

use super::{PreparedVerifyingKey, Proof, VerifyingKey};
use ark_ff::PrimeField;
use ark_relations::r1cs::{Result as R1CSResult, SynthesisError};
use core::ops::{AddAssign, Neg};

use ark_std::end_timer;
use ark_std::start_timer;
/// Prepare the verifying key `vk` for use in proof verification.
pub fn prepare_verifying_key<E: Pairing>(vk: &VerifyingKey<E>) -> PreparedVerifyingKey<E> {
    PreparedVerifyingKey {
        vk: vk.clone(),
        alpha_g1_beta_g2: E::pairing(vk.alpha_g1, vk.beta_g2).0,
        gamma_g2_neg_pc: vk.gamma_g2.into_group().neg().into_affine().into(),
        delta_g2_neg_pc: vk.delta_g2.into_group().neg().into_affine().into(),
    }
}

impl<E: Pairing, QAP: R1CSToQAP> CcGroth16<E, QAP> {
    pub fn prepare_inputs(
        pvk: &PreparedVerifyingKey<E>,
        public_inputs: &[E::ScalarField],
    ) -> R1CSResult<E::G1> {
        if (public_inputs.len() + 1 + DATA_SET.Data_size) != pvk.vk.gamma_abc_g1.len() {
            return Err(SynthesisError::MalformedVerifyingKey);
        }

        let mut g_ic = pvk.vk.gamma_abc_g1[0].into_group();
        for (i, b) in public_inputs.iter().zip(pvk.vk.gamma_abc_g1.iter().skip(1)) {
            g_ic.add_assign(&b.mul_bigint(i.into_bigint()));
        }

        Ok(g_ic)
    }
    /// Verify a Groth16 proof `proof` against the prepared verification key `pvk` and prepared public
    /// inputs. This should be preferred over [`verify_proof`] if the instance's public inputs are
    /// known in advance.
    pub fn verify_proof_with_prepared_inputs(
        pvk: &PreparedVerifyingKey<E>,
        proof: &Proof<E>,
        prepared_inputs: &E::G1,
    ) -> R1CSResult<bool> {
        let verifier_time = start_timer!(|| "ccGroth16::Verifier");
        let miller_loop_time = start_timer!(|| "Compute miller loop");
        let qap = E::multi_miller_loop(
            [
                <E::G1Affine as Into<E::G1Prepared>>::into(proof.a),
                <E::G1Affine as Into<E::G1Prepared>>::into(
                    (proof.cm + prepared_inputs).into_affine(),
                ),
                proof.c.into(),
            ],
            [
                proof.b.into(),
                pvk.gamma_g2_neg_pc.clone(),
                pvk.delta_g2_neg_pc.clone(),
            ],
        );
        end_timer!(miller_loop_time);
        let finalize_time = start_timer!(|| "Finalize exponentiation");
        let test = E::final_exponentiation(qap).ok_or(SynthesisError::UnexpectedIdentity)?;
        end_timer!(finalize_time);
        end_timer!(verifier_time);

        Ok(test.0 == pvk.alpha_g1_beta_g2)
    }

    /// Verify a Groth16 proof `proof` against the prepared verification key `pvk`,
    /// with respect to the instance `public_inputs`.
    pub fn verify_proof(
        pvk: &PreparedVerifyingKey<E>,
        proof: &Proof<E>,
        public_inputs: &[E::ScalarField],
    ) -> R1CSResult<bool> {
        let prepared_inputs = Self::prepare_inputs(pvk, public_inputs)?;
        Self::verify_proof_with_prepared_inputs(pvk, proof, &prepared_inputs)
    }
}
