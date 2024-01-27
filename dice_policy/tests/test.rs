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

//! Test libsdice_policy_builder & libdice_policy. Uses `rdroidtest` attribute macro.

use ciborium::{cbor, Value};
use coset::{AsCborValue, CborSerializable, CoseKey, CoseSign1, Header, ProtectedHeader};
use dice_policy::{Constraint, DicePolicy, NodeConstraints};
use dice_policy_builder::{policy_for_dice_chain, ConstraintSpec, ConstraintType, MissingAction};
use rdroidtest::rdroidtest;

const AUTHORITY_HASH: i64 = -4670549;
const CONFIG_DESC: i64 = -4670548;
const COMPONENT_NAME: i64 = -70002;
const COMPONENT_VERSION: i64 = -70003;
const SECURITY_VERSION: i64 = -70005;
const KEY_MODE: i64 = -4670551;
const EXPLICIT_KEY_DICE_CERT_CHAIN_VERSION: u64 = 1;

// Helper struct to encapsulate artifacts that are useful for unit tests.
struct TestArtifacts {
    // A dice chain.
    input_dice: Vec<u8>,
    // A list of ConstraintSpec that can be applied on the input_dice to get a dice policy.
    constraint_spec: Vec<ConstraintSpec>,
    // The expected dice policy if above constraint_spec is applied to input_dice.
    expected_dice_policy: DicePolicy,
    // Another dice chain, which is almost same as the input_dice, but (roughly) imitates
    // an 'updated' one, ie, some int entries are higher than corresponding entry
    // in input_chain.
    updated_input_dice: Vec<u8>,
}

impl TestArtifacts {
    // Get an example instance of TestArtifacts. This uses a hard coded, hypothetical
    // chain of certificates & a list of constraint_spec on this.
    fn get_example() -> Self {
        const EXAMPLE_NUM_1: i64 = 59765;
        const EXAMPLE_NUM_2: i64 = 59766;
        const EXAMPLE_STRING: &str = "testing_dice_policy";
        const UNCONSTRAINED_STRING: &str = "unconstrained_string";
        const ANOTHER_UNCONSTRAINED_STRING: &str = "another_unconstrained_string";

        let rot_key = Value::Bytes(CoseKey::default().to_vec().unwrap());
        let input_dice = Self::get_dice_chain_helper(
            rot_key.clone(),
            EXAMPLE_NUM_1,
            EXAMPLE_STRING,
            UNCONSTRAINED_STRING,
        );

        // Now construct constraint_spec on the input dice, note this will use the keys
        // which are also hardcoded within the get_dice_chain_helper.

        let constraint_spec = vec![
            ConstraintSpec::new(ConstraintType::ExactMatch, vec![1], MissingAction::Fail),
            // Notice how key "2" is (deliberately) absent in ConstraintSpec
            // so policy should not constrain it.
            ConstraintSpec::new(ConstraintType::GreaterOrEqual, vec![3, 100], MissingAction::Fail),
        ];
        let expected_dice_policy = DicePolicy {
            version: 1,
            node_constraints_list: Box::new([
                NodeConstraints(Box::new([Constraint::new(
                    ConstraintType::ExactMatch as u16,
                    vec![],
                    Value::from(EXPLICIT_KEY_DICE_CERT_CHAIN_VERSION),
                )
                .unwrap()])),
                NodeConstraints(Box::new([Constraint::new(
                    ConstraintType::ExactMatch as u16,
                    vec![],
                    rot_key.clone(),
                )
                .unwrap()])),
                NodeConstraints(Box::new([
                    Constraint::new(
                        ConstraintType::ExactMatch as u16,
                        vec![1],
                        Value::Text(EXAMPLE_STRING.to_string()),
                    )
                    .unwrap(),
                    Constraint::new(
                        ConstraintType::GreaterOrEqual as u16,
                        vec![3, 100],
                        Value::from(EXAMPLE_NUM_1),
                    )
                    .unwrap(),
                ])),
            ]),
        };

        let updated_input_dice = Self::get_dice_chain_helper(
            rot_key,
            EXAMPLE_NUM_2,
            EXAMPLE_STRING,
            ANOTHER_UNCONSTRAINED_STRING,
        );
        Self { input_dice, constraint_spec, expected_dice_policy, updated_input_dice }
    }

    // Helper method method to generate a dice chain with a given rot_key.
    // Other arguments are ad-hoc values in the nested map. Callers use these to
    // construct appropriate constrains in dice policies.
    fn get_dice_chain_helper(
        rot_key: Value,
        version: i64,
        constrained_string: &str,
        unconstrained_string: &str,
    ) -> Vec<u8> {
        let nested_payload = cbor!({
            100 => version
        })
        .unwrap();

        let payload = cbor!({
            1 => constrained_string,
            2 => unconstrained_string,
            3 => Value::Bytes(nested_payload.to_vec().unwrap()),
        })
        .unwrap();
        let payload = payload.to_vec().unwrap();
        let dice_node = CoseSign1 {
            protected: ProtectedHeader::default(),
            unprotected: Header::default(),
            payload: Some(payload),
            signature: b"ddef".to_vec(),
        }
        .to_cbor_value()
        .unwrap();
        let input_dice = Value::Array(vec![
            Value::from(EXPLICIT_KEY_DICE_CERT_CHAIN_VERSION),
            rot_key,
            dice_node,
        ]);

        input_dice.to_vec().unwrap()
    }
}

#[rdroidtest]
fn policy_structure_check() {
    let example = TestArtifacts::get_example();
    let policy = policy_for_dice_chain(&example.input_dice, &example.constraint_spec).unwrap();

    // Assert policy is exactly as expected!
    assert_eq!(policy, example.expected_dice_policy);
}

#[rdroidtest]
fn policy_enc_dec_test() {
    // An example dice policy
    let dice_policy: DicePolicy = TestArtifacts::get_example().expected_dice_policy;
    // Encode & then decode back!
    let dice_policy_enc_dec =
        DicePolicy::from_slice(&dice_policy.clone().to_vec().unwrap()).unwrap();
    assert_eq!(dice_policy, dice_policy_enc_dec);
}

#[rdroidtest]
fn policy_matches_original_dice_chain() {
    let example = TestArtifacts::get_example();
    policy_for_dice_chain(&example.input_dice, &example.constraint_spec)
        .unwrap()
        .matches_dice_chain(&example.input_dice)
        .unwrap();
}

#[rdroidtest]
fn policy_matches_updated_dice_chain() {
    let example = TestArtifacts::get_example();
    policy_for_dice_chain(&example.input_dice, &example.constraint_spec)
        .unwrap()
        .matches_dice_chain(&example.updated_input_dice)
        .unwrap();
}

#[rdroidtest]
fn policy_mismatch_downgraded_dice_chain() {
    let example = TestArtifacts::get_example();
    assert!(
        policy_for_dice_chain(&example.updated_input_dice, &example.constraint_spec)
            .unwrap()
            .matches_dice_chain(&example.input_dice)
            .is_err(),
        "The (downgraded) dice chain matched the policy constructed out of the 'updated'\
            dice chain!!"
    );
}

#[rdroidtest]
fn policy_constructional_required_constraint() {
    let mut example = TestArtifacts::get_example();
    // The constraint_path [9,8,7] is not present in example.input_dice
    example.constraint_spec.push(ConstraintSpec::new(
        ConstraintType::ExactMatch,
        vec![9, 8, 7],
        MissingAction::Fail,
    ));
    assert!(
        policy_for_dice_chain(&example.input_dice, &example.constraint_spec).is_err(),
        "DicePolicy creation should've failed on Required constraint"
    );
}

#[rdroidtest]
fn policy_constructional_optional_constraint() {
    let mut example = TestArtifacts::get_example();
    // The constraint_path [9,8,7] is not present in example.input_dice
    example.constraint_spec.push(ConstraintSpec::new(
        ConstraintType::ExactMatch,
        vec![9, 8, 7],
        MissingAction::Ignore,
    ));
    // However for optional constraint, policy construction should succeed!
    _ = policy_for_dice_chain(&example.input_dice, &example.constraint_spec).unwrap()
}

#[rdroidtest]
fn policy_dice_size_is_same() {
    // This is the number of certs in compos bcc (including the first ROT)
    // To analyze a bcc use hwtrust tool from /tools/security/remote_provisioning/hwtrust
    // `hwtrust --verbose dice-chain [path]/composbcc`
    const COMPOS_CHAIN_SIZE_EXPLICIT_KEY: usize = 6;
    let input_dice = include_bytes!("./testdata/compos_chain_explicit");
    let constraint_spec = [
        ConstraintSpec::new(ConstraintType::ExactMatch, vec![AUTHORITY_HASH], MissingAction::Fail),
        ConstraintSpec::new(ConstraintType::ExactMatch, vec![KEY_MODE], MissingAction::Fail),
        ConstraintSpec::new(
            ConstraintType::ExactMatch,
            vec![CONFIG_DESC, COMPONENT_NAME],
            MissingAction::Fail,
        ),
        ConstraintSpec::new(
            ConstraintType::GreaterOrEqual,
            vec![CONFIG_DESC, COMPONENT_VERSION],
            MissingAction::Ignore,
        ),
        ConstraintSpec::new(
            ConstraintType::GreaterOrEqual,
            vec![CONFIG_DESC, SECURITY_VERSION],
            MissingAction::Ignore,
        ),
    ];
    let policy = policy_for_dice_chain(input_dice, &constraint_spec).unwrap();
    assert_eq!(policy.node_constraints_list.len(), COMPOS_CHAIN_SIZE_EXPLICIT_KEY);
    // Check that original dice chain matches the policy.
    policy.matches_dice_chain(input_dice).unwrap();
}

#[rdroidtest]
fn policy_matcher_builder_in_sync() {
    // DicePolicy builder & matcher are closely coupled.
    assert_eq!(
        dice_policy::DICE_POLICY_VERSION,
        dice_policy_builder::SUPPORTED_DICE_POLICY_VERSION
    );
}

rdroidtest::test_main!();
