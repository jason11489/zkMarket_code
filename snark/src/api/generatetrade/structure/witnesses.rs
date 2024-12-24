use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_std::collections::HashMap;
use ark_std::fmt;
use ark_std::hash::Hash;
use ark_std::marker::PhantomData;
use ark_std::Zero;
use num_bigint::BigUint;
use serde::de::{self, MapAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct generatetradeCircuitWitnesses<C: CurveGroup>
where
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
{
    // witnesses
    pub r: C::BaseField,
    pub h_k: C::BaseField,
    pub ENA_writer: C::BaseField,
    pub pk_cons: Vec<C::BaseField>,
    pub pk_peer: Vec<C::BaseField>,
    pub k_ENA: C::BaseField,
    pub fee: C::BaseField,

    pub CT_ord_key: Vec<C::BaseField>,
    pub CT_ord_key_x: C::BaseField,
    pub CT_r: C::ScalarField,
}

impl<C: CurveGroup> Serialize for generatetradeCircuitWitnesses<C>
where
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("generatetradeCircuitWitnesses", 10)?;
        let multi_values_tuple = vec![
            ("pk_cons", self.pk_cons.clone()),
            ("pk_peer", self.pk_peer.clone()),
            ("CT_ord_key", self.CT_ord_key.clone()),
        ];
        // "r", "leaf_pos" is not C::BaseField values
        let single_values_tuple = vec![
            ("r", self.r.clone().to_string()),
            ("h_k", self.h_k.clone().to_string()),
            ("ENA_writer", self.ENA_writer.clone().to_string()),
            ("k_ENA", self.k_ENA.clone().to_string()),
            ("fee", self.fee.clone().to_string()),
            ("CT_ord_key_x", self.CT_ord_key_x.clone().to_string()),
            ("CT_r", self.CT_r.clone().to_string()),
        ];

        for (key, value) in multi_values_tuple {
            let resolved = &value
                .iter()
                .map(|i| {
                    let s;
                    if C::BaseField::is_zero(&i) {
                        s = "0".to_string();
                    } else {
                        s = i.to_string();
                    }
                    s.parse::<BigUint>().unwrap().to_str_radix(16)
                })
                .collect::<Vec<_>>();
            state.serialize_field(key, resolved)?;
        }

        for (key, value) in single_values_tuple {
            // already stringified
            let s;
            if value.is_empty() {
                s = "0".to_string();
            } else {
                s = value;
            }
            let resolved = &s.parse::<BigUint>().unwrap().to_str_radix(16);
            state.serialize_field(key, resolved)?;
        }
        state.end()
    }
}

impl<'de, C: CurveGroup> Deserialize<'de> for generatetradeCircuitWitnesses<C>
where
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[allow(non_camel_case_types)]
        #[derive(Eq, PartialEq, Hash)]
        enum Field {
            r,
            h_k,
            ENA_writer,
            pk_cons,
            pk_peer,
            k_ENA,
            fee,
            CT_ord_key,
            CT_ord_key_x,
            CT_r,
        }

        impl<'de> Deserialize<'de> for Field {
            fn deserialize<D>(deserializer: D) -> Result<Field, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct FieldVisitor;

                impl<'de> Visitor<'de> for FieldVisitor {
                    type Value = Field;

                    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                        formatter.write_str(
                            "`r` , `h_k`, `ENA_writer`, `pk_cons`, `pk_peer`, `k_ENA`, `fee`, `CT_ord_key`, 
                        `CT_ord_key_x`, `CT_r`, ",
                        )
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Field, E>
                    where
                        E: de::Error,
                    {
                        match value {
                            "r" => Ok(Field::r),
                            "h_k" => Ok(Field::h_k),
                            "ENA_writer" => Ok(Field::ENA_writer),
                            "pk_cons" => Ok(Field::pk_cons),
                            "pk_peer" => Ok(Field::pk_peer),
                            "k_ENA" => Ok(Field::k_ENA),
                            "fee" => Ok(Field::fee),
                            "CT_ord_key" => Ok(Field::CT_ord_key),
                            "CT_ord_key_x" => Ok(Field::CT_ord_key_x),
                            "CT_r" => Ok(Field::CT_r),
                            _ => Err(de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct generatetradeCircuitWitnessesVisitor<C: CurveGroup>
        where
            C::BaseField: PrimeField + Absorb,
        {
            _c: PhantomData<C>,
        }
        impl<'de, C: CurveGroup> Visitor<'de> for generatetradeCircuitWitnessesVisitor<C>
        where
            <C as CurveGroup>::BaseField: PrimeField + Absorb,
        {
            type Value = generatetradeCircuitWitnesses<C>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct generatetradeCircuitWitnesses")
            }

            fn visit_map<V>(self, mut map: V) -> Result<generatetradeCircuitWitnesses<C>, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut multi_values_map: HashMap<Field, (&str, Option<Vec<C::BaseField>>)> =
                    HashMap::from([
                        (Field::pk_cons, ("pk_cons", None)),
                        ((Field::pk_peer, ("pk_peer", None))),
                        ((Field::CT_ord_key, ("CT_ord_key", None))),
                    ]);

                let mut single_values_map: HashMap<Field, (&str, Option<C::BaseField>)> =
                    HashMap::from([
                        (Field::r, ("r", None)),
                        (Field::h_k, ("h_k", None)),
                        (Field::ENA_writer, ("ENA_writer", None)),
                        (Field::k_ENA, ("k_ENA", None)),
                        (Field::fee, ("fee", None)),
                        (Field::CT_ord_key_x, ("CT_ord_key_x", None)),
                    ]);

                let mut CT_r = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        // handle multi values
                        Field::pk_cons | Field::pk_peer | Field::CT_ord_key => {
                            let (name, value) = multi_values_map.get(&key).unwrap();
                            if value.is_some() {
                                return Err(de::Error::duplicate_field(name));
                            }
                            let v: Vec<String> = map.next_value()?;
                            let updated = Some(
                                v.iter()
                                    .map(|i| {
                                        C::BaseField::from(
                                            BigUint::parse_bytes(i.as_bytes(), 16).unwrap(),
                                        )
                                    })
                                    .collect(),
                            );
                            multi_values_map.insert(key, (*name, updated));
                        }
                        // handle single values
                        Field::r
                        | Field::h_k
                        | Field::ENA_writer
                        | Field::pk_cons
                        | Field::pk_peer
                        | Field::k_ENA
                        | Field::fee
                        | Field::CT_ord_key
                        | Field::CT_ord_key_x => {
                            let (name, value) = single_values_map.get(&key).unwrap();
                            if value.is_some() {
                                return Err(de::Error::duplicate_field(name));
                            }
                            let s: String = map.next_value()?;
                            let updated = Some(C::BaseField::from(
                                BigUint::parse_bytes(s.as_bytes(), 16).unwrap(),
                            ));
                            single_values_map.insert(key, (*name, updated));
                        }
                        // handle exceptions
                        Field::CT_r => {
                            if CT_r.is_some() {
                                return Err(de::Error::duplicate_field("CT_r"));
                            }
                            let s: String = map.next_value()?;
                            CT_r = Some(C::ScalarField::from(
                                BigUint::parse_bytes(s.as_bytes(), 16).unwrap(),
                            ));
                        }
                    }
                }

                // handle assign error
                for (_, (name, value)) in single_values_map.iter() {
                    value.ok_or_else(|| de::Error::missing_field(name))?;
                }

                let CT_r = CT_r.ok_or_else(|| de::Error::missing_field("CT_r"))?;

                // helper function to decrease lines...
                fn unwrap_map<K, V, W>(m: &HashMap<K, (V, Option<W>)>, k: K) -> &W
                where
                    K: PartialEq + Eq + Hash,
                {
                    let (_, v) = m.get(&k).unwrap();
                    v.as_ref().unwrap()
                }

                Ok(generatetradeCircuitWitnesses {
                    r: unwrap_map(&single_values_map, Field::r).clone(),
                    h_k: unwrap_map(&single_values_map, Field::h_k).clone(),
                    ENA_writer: unwrap_map(&single_values_map, Field::ENA_writer).clone(),
                    pk_cons: unwrap_map(&multi_values_map, Field::pk_cons).clone(),
                    pk_peer: unwrap_map(&multi_values_map, Field::pk_peer).clone(),
                    k_ENA: unwrap_map(&single_values_map, Field::k_ENA).clone(),
                    fee: unwrap_map(&single_values_map, Field::fee).clone(),
                    CT_ord_key: unwrap_map(&multi_values_map, Field::CT_ord_key).clone(),
                    CT_ord_key_x: unwrap_map(&single_values_map, Field::CT_ord_key_x).clone(),
                    CT_r,
                })
            }
        }
        const FIELDS: &'static [&'static str] = &[
            "r",
            "h_k",
            "ENA_writer",
            "pk_cons",
            "pk_peer",
            "k_ENA",
            "fee",
            "CT_ord_key",
            "CT_ord_key_x",
            "CT_r",
        ];
        deserializer.deserialize_struct(
            "generatetradeCircuitWitnesses<C>",
            FIELDS,
            generatetradeCircuitWitnessesVisitor { _c: PhantomData },
        )
    }
}
