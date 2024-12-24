use crate::gadget::hashes;
use crate::gadget::hashes::constraints::CRHSchemeGadget;
use crate::gadget::hashes::mimc7;
use crate::gadget::hashes::mimc7::constraints::MiMCGadget;
use crate::Error;

use crate::gadget::symmetric_encrytions::constraints::SymmetricEncryptionGadget;
use crate::gadget::symmetric_encrytions::symmetric;
use crate::gadget::symmetric_encrytions::symmetric::constraints::SymmetricEncryptionSchemeGadget;

use crate::gadget::public_encryptions::elgamal;
use crate::gadget::public_encryptions::elgamal::constraints::ElGamalEncGadget;
use crate::gadget::public_encryptions::AsymmetricEncryptionGadget;

use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::{fields::fp::FpVar, prelude::AllocVar};
use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError};
use ark_std::marker::PhantomData;

use super::MockingCircuit;

pub type ConstraintF<C> = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;
#[allow(non_snake_case)]
#[derive(Clone)]

pub struct generatetradeCircuit<C: CurveGroup, GG: CurveVar<C, ConstraintF<C>>>
where
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
{
    // constant
    pub rc: mimc7::Parameters<C::BaseField>,
    pub G: elgamal::Parameters<C>,

    // statement
    pub cm: Option<C::BaseField>,
    pub G_r: Option<C::Affine>,
    pub c1: Option<C::Affine>,
    pub CT_ord: Option<Vec<C::BaseField>>,
    pub ENA_before: Option<Vec<C::BaseField>>,
    pub ENA_after: Option<Vec<C::BaseField>>,

    // witnesses
    pub r: Option<C::BaseField>,
    pub h_k: Option<C::BaseField>,
    pub ENA_writer: Option<C::BaseField>,
    pub pk_cons: Option<elgamal::PublicKey<C>>,
    pub pk_peer: Option<elgamal::PublicKey<C>>,
    pub k_ENA: Option<symmetric::SymmetricKey<C::BaseField>>,
    pub fee: Option<C::BaseField>,

    pub CT_ord_key: Option<elgamal::Plaintext<C>>,
    pub CT_ord_key_x: Option<symmetric::SymmetricKey<C::BaseField>>,
    pub CT_r: Option<elgamal::Randomness<C>>,

    // directionSelector
    // intermediateHashWires
    pub _curve_var: PhantomData<GG>,
}

#[allow(non_snake_case)]
impl<C, GG> ConstraintSynthesizer<C::BaseField> for generatetradeCircuit<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, C::BaseField>,
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<C::BaseField>,
    ) -> Result<(), SynthesisError> {
        // constants
        let rc = hashes::mimc7::constraints::ParametersVar::new_constant(
            ark_relations::ns!(cs, "round constants"),
            self.rc,
        )?;
        let G = elgamal::constraints::ParametersVar::new_constant(
            ark_relations::ns!(cs, "generator"),
            self.G,
        )?;

        // statement
        let cm = FpVar::new_input(cs.clone(), || {
            self.cm.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let CT_ord: Vec<FpVar<C::BaseField>> =
            Vec::new_input(ark_relations::ns!(cs, "CT_ord"), || {
                self.CT_ord.ok_or(SynthesisError::AssignmentMissing)
            })?;
        let CT_ord = vec![
            symmetric::constraints::CiphertextVar {
                c: CT_ord[0].clone(),
                r: FpVar::zero(),
            },
            symmetric::constraints::CiphertextVar {
                c: CT_ord[1].clone(),
                r: FpVar::one(),
            },
            symmetric::constraints::CiphertextVar {
                c: CT_ord[2].clone(),
                r: FpVar::one() + FpVar::one(),
            },
            symmetric::constraints::CiphertextVar {
                c: CT_ord[3].clone(),
                r: FpVar::one() + FpVar::one() + FpVar::one(),
            },
            symmetric::constraints::CiphertextVar {
                c: CT_ord[4].clone(),
                r: FpVar::one() + FpVar::one() + FpVar::one() + FpVar::one(),
            },
        ];

        let ENA_before: Vec<FpVar<C::BaseField>> =
            Vec::new_input(ark_relations::ns!(cs, "ENA_before"), || {
                self.ENA_before.ok_or(SynthesisError::AssignmentMissing)
            })?;

        let ENA_before = vec![
            symmetric::constraints::CiphertextVar {
                r: ENA_before[0].clone(),
                c: ENA_before[1].clone(),
            },
            symmetric::constraints::CiphertextVar {
                r: ENA_before[0].clone() + FpVar::one(),
                c: ENA_before[2].clone(),
            },
            symmetric::constraints::CiphertextVar {
                r: ENA_before[0].clone() + FpVar::one() + FpVar::one(),
                c: ENA_before[3].clone(),
            },
        ];

        let ENA_after: Vec<FpVar<C::BaseField>> =
            Vec::new_input(ark_relations::ns!(cs, "ENA_after"), || {
                self.ENA_after.ok_or(SynthesisError::AssignmentMissing)
            })?;

        let ENA_after = vec![
            symmetric::constraints::CiphertextVar {
                r: ENA_after[0].clone(),
                c: ENA_after[1].clone(),
            },
            symmetric::constraints::CiphertextVar {
                r: ENA_after[0].clone() + FpVar::one(),
                c: ENA_after[2].clone(),
            },
            symmetric::constraints::CiphertextVar {
                r: ENA_after[0].clone() + FpVar::one() + FpVar::one(),
                c: ENA_after[3].clone(),
            },
        ];

        let c1 = elgamal::constraints::OutputVar::new_input(ark_relations::ns!(cs, "c1"), || {
            Ok((self.G_r.unwrap(), self.c1.unwrap()))
        })
        .unwrap();

        // witness

        let r = FpVar::new_witness(ark_relations::ns!(cs, "r"), || Ok(self.r.unwrap())).unwrap();
        let h_k =
            FpVar::new_witness(ark_relations::ns!(cs, "h_k"), || Ok(self.h_k.unwrap())).unwrap();

        let ENA_writer = FpVar::new_witness(ark_relations::ns!(cs, "ENA_writer"), || {
            self.ENA_writer.ok_or(SynthesisError::AssignmentMissing)
        })?; // ena_send

        let pk_cons = elgamal::constraints::PublicKeyVar::new_witness(
            ark_relations::ns!(cs, "pk_cons"),
            || self.pk_cons.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let binding = pk_cons.clone().pk.to_bits_le()?;
        let pk_cons_point_x = Boolean::le_bits_to_fp_var(&binding[..binding.len() / 2])?;
        let pk_cons_point_y = Boolean::le_bits_to_fp_var(&binding[binding.len() / 2..])?;

        let pk_peer = elgamal::constraints::PublicKeyVar::new_witness(
            ark_relations::ns!(cs, "pk_peer"),
            || self.pk_peer.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let k_ENA = symmetric::constraints::SymmetricKeyVar::new_witness(
            ark_relations::ns!(cs, "k_ENA"),
            || self.k_ENA.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let fee =
            FpVar::new_witness(ark_relations::ns!(cs, "fee"), || Ok(self.fee.unwrap())).unwrap();

        let CT_ord_key: elgamal::constraints::PlaintextVar<C, GG> =
            elgamal::constraints::PlaintextVar::new_witness(
                ark_relations::ns!(cs, "CT_ord_key"),
                || self.CT_ord_key.ok_or(SynthesisError::AssignmentMissing),
            )?;

        let CT_ord_key_x = symmetric::constraints::SymmetricKeyVar::new_witness(
            ark_relations::ns!(cs, "CT_ord_key_x"),
            || self.CT_ord_key_x.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let CT_r = elgamal::constraints::RandomnessVar::new_witness(
            ark_relations::ns!(cs, "CT_r"),
            || self.CT_r.ok_or(SynthesisError::AssignmentMissing),
        )?;

        // relation

        //check fee
        let after_ENA_value = SymmetricEncryptionSchemeGadget::<C::BaseField>::decrypt(
            rc.clone(),
            k_ENA.clone(),
            ENA_after[2].clone(),
        )
        .unwrap();

        let before_ENA_value = SymmetricEncryptionSchemeGadget::<C::BaseField>::decrypt(
            rc.clone(),
            k_ENA.clone(),
            ENA_before[2].clone(),
        )
        .unwrap();

        let hash_input = [
            ENA_writer.clone(),
            r.clone(),
            fee.clone(),
            h_k.clone(),
            pk_cons_point_x.clone(),
        ]
        .to_vec();
        let hash_output = MiMCGadget::<C::BaseField>::evaluate(&rc, &hash_input).unwrap();

        // check CT x
        let check_CT_k_point_x = CT_ord_key.plaintext.to_bits_le()?;
        let check_CT_k_point_x =
            Boolean::le_bits_to_fp_var(&check_CT_k_point_x[..check_CT_k_point_x.len() / 2])?;
        check_CT_k_point_x.enforce_equal(&CT_ord_key_x.k)?;

        println!(
            "check_CT_k_point_x: {:?}",
            check_CT_k_point_x.is_eq(&CT_ord_key_x.k)?.value()
        );

        // check c1

        let check_c_1 =
            ElGamalEncGadget::<C, GG>::encrypt(&G.clone(), &CT_ord_key.clone(), &CT_r, &pk_peer)
                .unwrap();

        c1.enforce_equal(&check_c_1)?;
        println!("c1: {:?}", c1.is_eq(&check_c_1)?.value());

        //check SE.Enc
        let Order: Vec<FpVar<C::BaseField>> = vec![
            pk_cons_point_x.clone(),
            pk_cons_point_y.clone(),
            r.clone(),
            fee.clone(),
            h_k.clone(),
        ];

        for (i, m) in Order.iter().enumerate() {
            let randomness = symmetric::constraints::RandomnessVar::new_constant(
                ark_relations::ns!(cs, "randomness"),
                symmetric::Randomness {
                    r: C::BaseField::from_bigint((i as u64).into()).unwrap(),
                },
            )?;

            let c = SymmetricEncryptionSchemeGadget::<C::BaseField>::encrypt(
                rc.clone(),
                randomness,
                CT_ord_key_x.clone(),
                symmetric::constraints::PlaintextVar { m: m.clone() },
            )
            .unwrap();

            c.enforce_equal(&CT_ord[i])?;
            println!("c: {:?}", c.is_eq(&CT_ord[i])?.value());
        }

        cm.enforce_equal(&hash_output)?;
        println!("cm: {:?}", cm.is_eq(&hash_output)?.value());
        fee.enforce_equal(&(before_ENA_value.clone().m - after_ENA_value.clone().m))?;
        println!(
            "fee: {:?}",
            fee.is_eq(&(before_ENA_value.clone().m - after_ENA_value.clone().m))?
                .value()
        );

        println!("total constraints num = {:?}", cs.num_constraints());

        Ok(())
    }
}

#[allow(non_snake_case)]
impl<C, GG> MockingCircuit<C, GG> for generatetradeCircuit<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, C::BaseField>,
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    type F = C::BaseField;
    type HashParam = mimc7::Parameters<Self::F>;
    type H = mimc7::MiMC<Self::F>;
    type Output = generatetradeCircuit<C, GG>;

    fn generate_circuit<R: ark_std::rand::Rng>(
        round_constants: Self::HashParam,
        rng: &mut R,
    ) -> Result<Self::Output, Error> {
        use crate::gadget::hashes::CRHScheme;
        use crate::gadget::public_encryptions::elgamal::ElGamal;
        use crate::gadget::public_encryptions::AsymmetricEncryptionScheme;
        use crate::gadget::symmetric_encrytions::SymmetricEncryption;

        use ark_ec::AffineRepr;
        use ark_std::One;
        use ark_std::UniformRand;

        let generator = C::generator().into_affine();
        let rc: mimc7::Parameters<<<C as CurveGroup>::Affine as AffineRepr>::BaseField> =
            round_constants;
        let elgamal_param: elgamal::Parameters<C> = elgamal::Parameters {
            generator: generator.clone(),
        };

        let sk: <<C as CurveGroup>::Affine as AffineRepr>::BaseField = Self::F::rand(rng);
        let cin_r: <<C as CurveGroup>::Affine as AffineRepr>::BaseField = Self::F::rand(rng);

        let k_ENA: symmetric::SymmetricKey<<<C as CurveGroup>::Affine as AffineRepr>::BaseField> =
            symmetric::SymmetricKey { k: sk };

        let random = vec![
            symmetric::Randomness { r: cin_r },
            symmetric::Randomness {
                r: cin_r + Self::F::one(),
            },
            symmetric::Randomness {
                r: cin_r + Self::F::one() + Self::F::one(),
            },
        ];

        let tk_addr: Self::F = Self::F::one();
        let tk_id: Self::F = Self::F::one();
        let v_ena_old: Self::F = Self::F::one() + Self::F::one();
        let v_ena_new: Self::F = Self::F::one();

        let ENA_before0 = symmetric::SymmetricEncryptionScheme::encrypt(
            rc.clone(),
            random[0].clone(),
            k_ENA.clone(),
            symmetric::Plaintext { m: tk_addr },
        )
        .unwrap();
        let ENA_before1 = symmetric::SymmetricEncryptionScheme::encrypt(
            rc.clone(),
            random[1].clone(),
            k_ENA.clone(),
            symmetric::Plaintext { m: tk_id },
        )
        .unwrap();
        let ENA_before2 = symmetric::SymmetricEncryptionScheme::encrypt(
            rc.clone(),
            random[2].clone(),
            k_ENA.clone(),
            symmetric::Plaintext { m: v_ena_old },
        )
        .unwrap();
        let ENA_before: Vec<Self::F> = vec![
            random[0].clone().r,
            ENA_before0.c,
            ENA_before1.c,
            ENA_before2.c,
        ];

        let ENA_after0 = symmetric::SymmetricEncryptionScheme::encrypt(
            rc.clone(),
            random[0].clone(),
            k_ENA.clone(),
            symmetric::Plaintext { m: tk_addr },
        )
        .unwrap();
        let ENA_after1 = symmetric::SymmetricEncryptionScheme::encrypt(
            rc.clone(),
            random[1].clone(),
            k_ENA.clone(),
            symmetric::Plaintext { m: tk_id },
        )
        .unwrap();
        let ENA_after2 = symmetric::SymmetricEncryptionScheme::encrypt(
            rc.clone(),
            random[2].clone(),
            k_ENA.clone(),
            symmetric::Plaintext { m: v_ena_new },
        )
        .unwrap();
        let ENA_after: Vec<Self::F> = vec![
            random[0].clone().r,
            ENA_after0.c,
            ENA_after1.c,
            ENA_after2.c,
        ];

        let fee: Self::F = Self::F::one();

        // cm check

        let ENA_writer: Self::F = Self::F::one();
        let r: Self::F = Self::F::one();
        let h_k: Self::F = Self::F::one();
        let (pk_cons, _) = ElGamal::keygen(&elgamal_param, rng).unwrap();
        let (pk_peer, _) = ElGamal::keygen(&elgamal_param, rng).unwrap();

        let (pk_cons_point_x, pk_cons_point_y) = pk_cons.xy().unwrap();
        let pk_cons_point_x = Self::F::from_bigint(pk_cons_point_x.into_bigint()).unwrap();

        let cm = Self::H::evaluate(
            &rc.clone(),
            [ENA_writer.clone(), r, fee, h_k, pk_cons_point_x.clone()].to_vec(),
        )
        .unwrap();

        //CT check

        let CT_ord_key = C::rand(rng).into_affine();
        let CT_ord_key_x = CT_ord_key.x().unwrap();
        let CT_ord_key_x = symmetric::SymmetricKey { k: *CT_ord_key_x };
        let mut CT_ord: Vec<_> = Vec::new();

        let CT_r = C::ScalarField::rand(rng);

        let random: elgamal::Randomness<C> = elgamal::Randomness { 0: CT_r };
        let (G_r, c1) = ElGamal::encrypt(&elgamal_param, &pk_peer, &CT_ord_key, &random).unwrap();

        let Order = vec![
            pk_cons_point_x.clone(),
            pk_cons_point_y.clone(),
            r.clone(),
            fee.clone(),
            h_k.clone(),
        ];

        Order.iter().enumerate().for_each(|(i, m)| {
            let random = symmetric::Randomness {
                r: Self::F::from_bigint((i as u64).into()).unwrap(),
            };
            let c = symmetric::SymmetricEncryptionScheme::encrypt(
                rc.clone(),
                random,
                CT_ord_key_x.clone(),
                symmetric::Plaintext { m: m.clone() },
            )
            .unwrap();

            CT_ord.push(c.c);
        });

        Ok(generatetradeCircuit {
            //constant
            rc: rc.clone(),
            G: elgamal_param,
            // statement
            cm: Some(cm),
            G_r: Some(G_r),
            c1: Some(c1),
            CT_ord: Some(CT_ord),
            ENA_before: Some(ENA_before),
            ENA_after: Some(ENA_after),
            //witness
            r: Some(r),
            h_k: Some(h_k),
            ENA_writer: Some(ENA_writer),
            pk_cons: Some(pk_cons),
            pk_peer: Some(pk_peer),
            k_ENA: Some(k_ENA),
            fee: Some(fee),

            CT_ord_key: Some(CT_ord_key),
            CT_ord_key_x: Some(CT_ord_key_x),
            CT_r: Some(random),

            _curve_var: std::marker::PhantomData,
        })
    }
}
