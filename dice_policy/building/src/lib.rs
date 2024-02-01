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

//! This library supports constructing Dice Policies on a Dice chains, enabling various ways to
//! specify the constraints. This adheres to the Dice Policy spec at DicePolicy.cddl & works with
//! the rust structs exported by libdice_policy.

#![allow(missing_docs)] // Sadly needed due to use of enumn::N

use ciborium::Value;
use dice_policy::{
    check_is_explicit_key_dice_chain, deserialize_cbor_array, lookup_in_nested_container,
    payload_value_from_cose_sign, Constraint, DicePolicy, NodeConstraints, DICE_POLICY_VERSION,
    EXACT_MATCH_CONSTRAINT, GREATER_OR_EQUAL_CONSTRAINT,
};
use enumn::N;

type Error = String;

/// Supported version of dice policy spec.
pub const SUPPORTED_DICE_POLICY_VERSION: u64 = 1;

/// Constraint Types supported in Dice policy.
#[repr(u16)]
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, N)]
pub enum ConstraintType {
    /// Enforce exact match criteria, indicating the policy should match
    /// if the dice chain has exact same specified values.
    ExactMatch = EXACT_MATCH_CONSTRAINT,
    /// Enforce Greater than or equal to criteria. When applied on security_version, this
    /// can be useful to set policy that matches dice chains with same or upgraded images.
    GreaterOrEqual = GREATER_OR_EQUAL_CONSTRAINT,
}

/// ConstraintSpec is used to specify which constraint type to apply and on which all values in a
/// DiceChainEntry. See documentation of `policy_for_dice_chain()` for examples.
pub struct ConstraintSpec {
    constraint_type: ConstraintType,
    // `path` is essentially a list of label/int.
    // It identifies which values (in a DiceChainEntry) to be applying constraints on.
    path: Vec<i64>,
    // If set to `Ignore`, the constraint is skipped if the `path` is missing in a
    // DiceChainEntry while constructing a policy. Note that this does not affect policy
    // matching.
    if_path_missing: MissingAction,
}

impl ConstraintSpec {
    /// Constraint the value corresponding to `path`. `constraint_type` specifies how and
    /// `if_path_missing` specifies what to do if the `path` is missing in a DiceChainEntry.
    pub fn new(
        constraint_type: ConstraintType,
        path: Vec<i64>,
        if_path_missing: MissingAction,
    ) -> Self {
        Self { constraint_type, path, if_path_missing }
    }
}

/// Used to define a `ConstraintSpec` requirement. This allows client to set behavior of
/// policy construction in case the `path` is missing in a DiceChainEntry.
#[derive(Eq, PartialEq)]
pub enum MissingAction {
    /// Indicates that a constraint `path` is required in each DiceChainEntry. Fail if missing!
    Fail,
    /// Indicates that a constraint `path` may be missing in some DiceChainEntry. Ignore!
    Ignore,
}

/// Construct a dice policy on a given dice chain.
/// This can be used by clients to construct a policy to seal secrets.
/// Constraints on all but (first & second) dice nodes is applied using constraint_spec
/// argument. For the first and second node (version and root public key), the constraint is
/// ExactMatch of the whole node.
///
/// # Arguments
/// `dice_chain`: The serialized CBOR encoded Dice chain, adhering to Explicit-key
/// DiceCertChain format. See definition at ExplicitKeyDiceCertChain.cddl
///
/// `constraint_spec`: List of constraints to be applied on dice node.
/// Each constraint is a ConstraintSpec object.
///
/// Note: Dice node is treated as a nested structure (map or array) (& so the lookup is done in
/// that fashion).
///
/// Examples of constraint_spec:
///  1. For exact_match on auth_hash & greater_or_equal on security_version
///    constraint_spec =[
///     (ConstraintType::ExactMatch, vec![AUTHORITY_HASH]),
///     (ConstraintType::GreaterOrEqual, vec![CONFIG_DESC, COMPONENT_NAME]),
///    ];
///
/// 2. For hypothetical (and highly simplified) dice chain:
///
///    [1, ROT_KEY, [{1 : 'a', 2 : {200 : 5, 201 : 'b'}}]]
///    The following can be used
///    constraint_spec =[
///     ConstraintSpec(ConstraintType::ExactMatch, vec![1]),         // exact_matches value 'a'
///     ConstraintSpec(ConstraintType::GreaterOrEqual, vec![2, 200]),// matches any value >= 5
///    ];
pub fn policy_for_dice_chain(
    explicit_key_dice_chain: &[u8],
    constraint_spec: &[ConstraintSpec],
) -> Result<DicePolicy, Error> {
    let dice_chain = deserialize_cbor_array(explicit_key_dice_chain)?;
    check_is_explicit_key_dice_chain(&dice_chain)?;
    let mut constraints_list: Vec<NodeConstraints> = Vec::with_capacity(dice_chain.len());
    let mut it = dice_chain.into_iter();
    // 1st & 2nd dice node of Explicit-key DiceCertChain format are
    // EXPLICIT_KEY_DICE_CERT_CHAIN_VERSION & DiceCertChainInitialPayload. The rest are
    // DiceChainEntry which is a CoseSign1.
    constraints_list.push(NodeConstraints(Box::new([Constraint::new(
        ConstraintType::ExactMatch as u16,
        Vec::new(),
        it.next().unwrap(),
    )?])));

    constraints_list.push(NodeConstraints(Box::new([Constraint::new(
        ConstraintType::ExactMatch as u16,
        Vec::new(),
        it.next().unwrap(),
    )?])));

    for (n, value) in it.enumerate() {
        let entry = payload_value_from_cose_sign(value)
            .map_err(|e| format!("Unable to get Cose payload at {n}: {e:?}"))?;
        constraints_list.push(
            constraints_on_dice_node(entry, constraint_spec)
                .map_err(|e| format!("Unable to get constraints for payload at {n}: {e:?}"))?,
        );
    }

    Ok(DicePolicy {
        version: DICE_POLICY_VERSION,
        node_constraints_list: constraints_list.into_boxed_slice(),
    })
}

// Take the ['node_payload'] of a dice node & construct the [`NodeConstraints`] on it. If the value
// corresponding to the a [`constraint_spec`] is not present in payload & iff it is marked
// `MissingAction::Ignore`, the corresponding constraint will be missing from the NodeConstraints.
fn constraints_on_dice_node(
    node_payload: Value,
    constraint_spec: &[ConstraintSpec],
) -> Result<NodeConstraints, Error> {
    let mut node_constraints: Vec<Constraint> = Vec::with_capacity(constraint_spec.len());
    for constraint_item in constraint_spec {
        let constraint_path = constraint_item.path.to_vec();
        if constraint_path.is_empty() {
            return Err("Expected non-empty key spec".to_string());
        }
        match lookup_in_nested_container(&node_payload, &constraint_path)? {
            Some(val) => {
                let constraint =
                    Constraint::new(constraint_item.constraint_type as u16, constraint_path, val)?;
                node_constraints.push(constraint);
            }
            None => {
                if constraint_item.if_path_missing == MissingAction::Ignore {
                    log::warn!("Value not found for {constraint_path:?}, - skipping!")
                } else {
                    return Err(format!(
                        "Value not found for : {constraint_path:?}, constraint\
                         spec is marked to fail on missing path"
                    ));
                }
            }
        }
    }
    Ok(NodeConstraints(node_constraints.into_boxed_slice()))
}
