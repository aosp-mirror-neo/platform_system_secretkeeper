/*
 * Copyright (C) 2023 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! A “DICE policy” is a format for setting constraints on a DICE chain. A DICE chain policy
//! verifier takes a policy and a DICE chain, and returns a boolean indicating whether the
//! DICE chain meets the constraints set out on a policy.
//!
//! This forms the foundation of DICE Policy aware Authentication (DPA-Auth), where the server
//! authenticates a client by comparing its dice chain against a set policy.
//!
//! Another use is "sealing", where clients can use an appropriately constructed dice policy to
//! seal a secret. Unsealing is only permitted if dice chain of the component requesting unsealing
//! complies with the policy.
//!
//! A typical policy will assert things like:
//! # DK_pub must have this value
//! # The DICE chain must be exactly five certificates long
//! # authorityHash in the third certificate must have this value
//! securityVersion in the fourth certificate must be an integer greater than 8
//!
//! These constraints used to express policy are (for now) limited to following 2 types:
//! 1. Exact Match: useful for enforcing rules like authority hash should be exactly equal.
//! 2. Greater than or equal to: Useful for setting policies that seal
//!    Anti-rollback protected entities (should be accessible to versions >= present).
//!
//! DICE Policy CDDL (keep in sync with DicePolicy.cddl):
//!
//! ```
//! dicePolicy = [
//! 1, ; dice policy version
//! + nodeConstraintList ; for each entry in dice chain
//! ]
//!
//! nodeConstraintList = [
//!     * nodeConstraint
//! ]
//!
//! ; We may add a hashConstraint item later
//! nodeConstraint = exactMatchConstraint / geConstraint
//!
//! exactMatchConstraint = [1, keySpec, value]
//! geConstraint = [2, keySpec, int]
//!
//! keySpec = [value+]
//!
//! value = bool / int / tstr / bstr
//! ```

#![no_std]

extern crate alloc;
use alloc::borrow::Cow;
use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;
use ciborium::Value;
use core::iter::zip;
use coset::{AsCborValue, CborSerializable, CoseError, CoseError::UnexpectedItem, CoseSign1};
type Error = String;

/// Version of the DICE policy spec
pub const DICE_POLICY_VERSION: u64 = 1;
/// Identifier for `exactMatchConstraint` as per spec
pub const EXACT_MATCH_CONSTRAINT: u16 = 1;
/// Identifier for `geConstraint` as per spec
pub const GREATER_OR_EQUAL_CONSTRAINT: u16 = 2;

/// Given an Android dice chain, check if it matches the given policy. This method returns
/// Ok(()) in case of successful match, otherwise returns error in case of failure.
pub fn chain_matches_policy(dice_chain: &[u8], policy: &[u8]) -> Result<(), Error> {
    DicePolicy::from_slice(policy)
        .map_err(|e| format!("DicePolicy decoding failed {e}"))?
        .matches_dice_chain(dice_chain)
        .map_err(|e| format!("DicePolicy matching failed {e}"))?;
    Ok(())
}

// TODO(b/291238565): (nested_)key & value type should be (bool/int/tstr/bstr). Status quo, only
// integer (nested_)key is supported.
// and maybe convert it into struct.
/// Each constraint (on a dice node) is a tuple: (ConstraintType, constraint_path, value)
/// This is Rust equivalent of `nodeConstraint` from CDDL above. Keep in sync!
#[derive(Clone, Debug, PartialEq)]
pub struct Constraint(u16, Vec<i64>, Value);

impl Constraint {
    /// Construct a new Constraint
    pub fn new(constraint_type: u16, path: Vec<i64>, value: Value) -> Result<Self, Error> {
        if constraint_type != EXACT_MATCH_CONSTRAINT
            && constraint_type != GREATER_OR_EQUAL_CONSTRAINT
        {
            return Err(format!("Invalid Constraint type: {constraint_type}"));
        }
        Ok(Self(constraint_type, path, value))
    }
}

impl AsCborValue for Constraint {
    fn from_cbor_value(value: Value) -> Result<Self, CoseError> {
        let [constrained_type, constraint_path, val] = value
            .into_array()
            .map_err(|_| UnexpectedItem("-", "Array"))?
            .try_into()
            .map_err(|_| UnexpectedItem("Array", "Array of size 3"))?;
        let constrained_type: u16 = value_to_integer(&constrained_type)?
            .try_into()
            .map_err(|_| UnexpectedItem("Integer", "u16"))?;
        let path_res: Vec<i64> = constraint_path
            .into_array()
            .map_err(|_| UnexpectedItem("-", "Array"))?
            .iter()
            .map(value_to_integer)
            .collect::<Result<_, _>>()?;
        Ok(Self(constrained_type, path_res, val))
    }

    fn to_cbor_value(self) -> Result<Value, CoseError> {
        Ok(Value::Array(vec![
            Value::from(self.0),
            Value::Array(self.1.into_iter().map(Value::from).collect()),
            self.2,
        ]))
    }
}

/// List of all constraints on a dice node.
/// This is Rust equivalent of `nodeConstraintList` in the CDDL above. Keep in sync!
#[derive(Clone, Debug, PartialEq)]
pub struct NodeConstraints(pub Box<[Constraint]>);

impl AsCborValue for NodeConstraints {
    fn from_cbor_value(value: Value) -> Result<Self, CoseError> {
        let res: Vec<Constraint> = value
            .into_array()
            .map_err(|_| UnexpectedItem("-", "Array"))?
            .into_iter()
            .map(Constraint::from_cbor_value)
            .collect::<Result<_, _>>()?;
        Ok(Self(res.into_boxed_slice()))
    }

    fn to_cbor_value(self) -> Result<Value, CoseError> {
        let res: Vec<Value> = self
            .0
            .into_vec()
            .into_iter()
            .map(Constraint::to_cbor_value)
            .collect::<Result<_, _>>()?;
        Ok(Value::Array(res))
    }
}

/// This is Rust equivalent of `dicePolicy` in the CDDL above. Keep in sync!
#[derive(Clone, Debug, PartialEq)]
pub struct DicePolicy {
    /// DICE policy version
    pub version: u64,
    /// List of `NodeConstraints`, one for each node of DICE chain.
    pub node_constraints_list: Box<[NodeConstraints]>,
}

impl AsCborValue for DicePolicy {
    fn from_cbor_value(value: Value) -> Result<Self, CoseError> {
        let mut arr = value.into_array().map_err(|_| UnexpectedItem("-", "Array"))?;
        if arr.len() < 2 {
            return Err(UnexpectedItem("Array", "Array with at least 2 elements"));
        }
        let (version, node_cons_list) = (value_to_integer(arr.first().unwrap())?, arr.split_off(1));
        let version: u64 = version.try_into().map_err(|_| UnexpectedItem("-", "u64"))?;
        let node_cons_list: Vec<NodeConstraints> = node_cons_list
            .into_iter()
            .map(NodeConstraints::from_cbor_value)
            .collect::<Result<_, _>>()?;
        Ok(Self { version, node_constraints_list: node_cons_list.into_boxed_slice() })
    }

    fn to_cbor_value(self) -> Result<Value, CoseError> {
        let mut res: Vec<Value> = Vec::with_capacity(1 + self.node_constraints_list.len());
        res.push(Value::from(self.version));
        for node_cons in self.node_constraints_list.into_vec() {
            res.push(node_cons.to_cbor_value()?)
        }
        Ok(Value::Array(res))
    }
}

impl CborSerializable for DicePolicy {}

impl DicePolicy {
    /// Matches this DICE policy against a serialized ExplicitKeyDiceCertChain.
    /// The method returns Ok() if the dice chain matches the constraints of this DICE policy,
    /// otherwise returns an error.
    ///
    /// For ExplicitKeyDiceCertChain CDDL see
    /// hardware/interfaces/security/authgraph/aidl/android/hardware/security/authgraph/ExplicitKeyDiceCertChain.cddl
    ///
    /// TODO(b/291238565) Create a separate error module for DicePolicy mismatches.
    pub fn matches_dice_chain(&self, explicit_key_dice_chain: &[u8]) -> Result<(), Error> {
        let explicit_key_dice_chain = deserialize_cbor_array(explicit_key_dice_chain)?;
        check_is_explicit_key_dice_chain(&explicit_key_dice_chain)?;
        if explicit_key_dice_chain.len() != self.node_constraints_list.len() {
            return Err(format!(
                "ExplicitKeyDiceCertChain size({}) does not match policy({})",
                explicit_key_dice_chain.len(),
                self.node_constraints_list.len()
            ));
        }

        for (n, (node_constraints, node)) in
            zip(self.node_constraints_list.iter(), explicit_key_dice_chain).enumerate()
        {
            let node = match n {
                0..=1 => node,
                n => payload_value_from_cose_sign(node)
                    .map_err(|e| format!("Unable to parse DiceChainEntry[{i}]: {e}", i = n - 2))?,
            };
            check_constraints_on_node(node_constraints, &node).map_err(|e| match n {
                0 => format!("Mismatch at ExplicitKeyDiceCertChain version: {e}"),
                1 => format!("Mismatch at DiceCertChainInitialPayload: {e}"),
                n => format!("Mismatch at DiceChainEntry[{i}]: {e}", i = n - 2),
            })?;
        }
        Ok(())
    }
}

/// Matches a single node against the corresponding node constraints of the DICE policy.
pub fn check_constraints_on_node(
    node_constraints: &NodeConstraints,
    node: &Value,
) -> Result<(), Error> {
    for constraint in node_constraints.0.iter() {
        check_constraint_on_node(constraint, node)?;
    }
    Ok(())
}

fn check_constraint_on_node(constraint: &Constraint, node: &Value) -> Result<(), Error> {
    let Constraint(cons_type, path, value_in_constraint) = constraint;
    let value_in_node = lookup_in_nested_container(node, path)?
        .ok_or(format!("Value not found for constraint {path:?}"))?;
    match *cons_type {
        EXACT_MATCH_CONSTRAINT => {
            if value_in_node != *value_in_constraint {
                return Err(format!(
                    "Constraint {path:?}): \
                    expected {value_in_constraint:?}; found {value_in_node:?}"
                ));
            }
        }
        GREATER_OR_EQUAL_CONSTRAINT => {
            let value_min = value_in_constraint
                .as_integer()
                .ok_or(format!("Invalid constraint {path:?}: expected a CBOR integer"))?;
            let value_in_node = value_in_node
                .as_integer()
                .ok_or(format!("Constraint {path:?}: expected a CBOR integer"))?;
            if value_in_node < value_min {
                return Err(format!(
                    "Constraint {path:?}: expected >= {value_min:?}; found {value_in_node:?}"
                ));
            }
        }
        cons_type => return Err(format!("Invalid constraint {path:?}: unknown type {cons_type}")),
    };
    Ok(())
}

/// Lookup value corresponding to constraint path in nested container.
/// This function recursively calls itself.
/// The depth of recursion is limited by the size of constraint_path.
pub fn lookup_in_nested_container(
    container: &Value,
    constraint_path: &[i64],
) -> Result<Option<Value>, Error> {
    if constraint_path.is_empty() {
        return Ok(Some(container.clone()));
    }
    let explicit_container = get_container_from_value(container)?;
    lookup_value_in_container(&explicit_container, constraint_path[0])
        .map_or_else(|| Ok(None), |val| lookup_in_nested_container(val, &constraint_path[1..]))
}

fn get_container_from_value(container: &Value) -> Result<Container<'_>, Error> {
    match container {
        // Value can be Map/Array/Encoded Map. Encoded Arrays are not yet supported (or required).
        // Note: Encoded Map is used for Configuration descriptor entry in DiceChainEntryPayload.
        Value::Bytes(b) => Value::from_slice(b)
            .map_err(|e| format!("{e}"))?
            .into_map()
            .map(|m| Container::Map(Cow::Owned(m)))
            .map_err(|e| format!("Expected a CBOR map: {e:?}")),
        Value::Map(map) => Ok(Container::Map(Cow::Borrowed(map))),
        Value::Array(array) => Ok(Container::Array(array)),
        _ => Err(format!("Expected an array/map/bytes {container:?}")),
    }
}

#[derive(Clone)]
enum Container<'a> {
    Map(Cow<'a, [(Value, Value)]>),
    Array(&'a Vec<Value>),
}

fn lookup_value_in_container<'a>(container: &'a Container<'a>, key: i64) -> Option<&'a Value> {
    match container {
        Container::Array(array) => array.get(key as usize),
        Container::Map(map) => {
            let key = Value::Integer(key.into());
            let mut val = None;
            for (k, v) in map.iter() {
                if k == &key {
                    val = Some(v);
                    break;
                }
            }
            val
        }
    }
}

/// This library only works with ExplicitKeyDiceCertChain format. Further we require it to have
/// at least 1 DiceChainEntry. Note that this is a lightweight check so that we fail early for
/// legacy chains.
pub fn check_is_explicit_key_dice_chain(dice_chain: &[Value]) -> Result<(), Error> {
    if matches!(dice_chain, [Value::Integer(_version), Value::Bytes(_public_key), _entry, ..]) {
        Ok(())
    } else {
        Err("Chain is not in explicit key format".to_string())
    }
}

/// Extract the payload from the COSE Sign
pub fn payload_value_from_cose_sign(cbor: Value) -> Result<Value, Error> {
    let sign1 =
        CoseSign1::from_cbor_value(cbor).map_err(|e| format!("Error extracting CoseSign1: {e}"))?;
    match sign1.payload {
        None => Err("Missing payload".to_string()),
        Some(payload) => Value::from_slice(&payload).map_err(|e| format!("{e}")),
    }
}

/// Decode a CBOR array
pub fn deserialize_cbor_array(cbor_array_bytes: &[u8]) -> Result<Vec<Value>, Error> {
    let cbor_array = Value::from_slice(cbor_array_bytes)
        .map_err(|e| format!("Unable to decode top-level CBOR: {e}"))?;
    let cbor_array =
        cbor_array.into_array().map_err(|e| format!("Expected an array found: {e:?}"))?;
    Ok(cbor_array)
}

// Useful to convert [`ciborium::Value`] to integer. Note we already downgrade the returned
// integer to i64 for convenience. Value::Integer is capable of storing bigger numbers.
fn value_to_integer(value: &Value) -> Result<i64, CoseError> {
    let num = value
        .as_integer()
        .ok_or(CoseError::UnexpectedItem("-", "Integer"))?
        .try_into()
        .map_err(|_| CoseError::UnexpectedItem("Integer", "i64"))?;
    Ok(num)
}
