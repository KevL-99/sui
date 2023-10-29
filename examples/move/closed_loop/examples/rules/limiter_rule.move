// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// An example of a Rule for the Closed Loop Token which limits the amount per
/// operation. Can be used to limit any action (eg transfer, toCoin, fromCoin).
module examples::limiter_rule {
    use std::string::String;
    use sui::vec_map::{Self, VecMap};
    use sui::tx_context::TxContext;
    use closed_loop::closed_loop::{
        Self as cl,
        TokenPolicy,
        TokenPolicyCap,
        ActionRequest
    };

    /// Trying to perform an action that exceeds the limit.
    const ELimitExceeded: u64 = 0;

    /// The Rule witness.
    struct Limiter has drop {}

    /// The Config object for the `lo
    struct Config has store, drop {
        /// Mapping of Action -> Limit
        limits: VecMap<String, u64>
    }

    /// Adds a limiter rule to the `TokenPolicy` with the given limit per
    /// operation.
    public fun add_for<T>(
        policy: &mut TokenPolicy<T>,
        cap: &TokenPolicyCap<T>,
        action: String,
        limit: u64,
        ctx: &mut TxContext
    ) {
        // if there's no stored config for the rule, add a new one
        if (!cl::has_rule_config<T, Limiter>(policy)) {
            let config = Config { limits: vec_map::empty() };
            cl::add_rule_config(Limiter {}, policy, cap, config, ctx);
        };

        let config = cl::rule_config_mut<T, Limiter, Config>(policy, cap);
        vec_map::insert(&mut config.limits, action, limit);
        cl::add_rule_for_action(Limiter {}, policy, cap, action, ctx);
    }

    /// Verifies that the request does not exceed the limit and adds an approval
    /// to the `ActionRequest`.
    public fun verify<T>(
        policy: &TokenPolicy<T>,
        request: &mut ActionRequest<T>,
        ctx: &mut TxContext
    ) {
        let config: &Config = cl::rule_config(Limiter {}, policy);
        let action_limit = *vec_map::get(&config.limits, &cl::name(request));

        assert!(cl::amount(request) <= action_limit, ELimitExceeded);
        cl::add_approval(Limiter {}, request, ctx);
    }

    /// Remove the Rule configuration for the given action. For types that have
    /// `drop` it's not necessary, but improves policy owner's experience.
    public fun remove_for<T>(
        policy: &mut TokenPolicy<T>,
        cap: &TokenPolicyCap<T>,
        action: String,
        ctx: &mut TxContext
    ) {
        cl::remove_rule_for_action<T, Limiter>(policy, cap, action, ctx);
        let config = cl::rule_config_mut<T, Limiter, Config>(policy, cap);
        vec_map::remove(
            &mut config.limits,
            &action
        );
    }
}

#[test_only]
module examples::limiter_rule_tests {
    use examples::limiter_rule as limiter;
    use std::string::utf8;
    use std::option::{none, /* some */};
    use closed_loop::closed_loop as cl;
    use closed_loop::closed_loop_tests as test;

    #[test]
    // Scenario: add a limiter rule for 100 tokens per operation, verify that
    // the request with 100 tokens is confirmed
    fun add_limiter_default() {
        let ctx = &mut sui::tx_context::dummy();
        let (policy, cap) = test::get_policy(ctx);

        limiter::add_for(&mut policy, &cap, utf8(b"action"), 100, ctx);

        let request = cl::new_request(utf8(b"action"), 100, none(), none(), ctx);

        limiter::verify(&policy, &mut request, ctx);

        cl::confirm_request(&mut policy, request, ctx);
        test::return_policy(policy, cap);
    }

    #[test]
    // Scenario: add a limiter rule for 100 tokens per operation, verify that
    // the request with 100 tokens is confirmed; then remove the rule and verify
    // that the request with 100 tokens is not confirmed and repeat step (1)
    fun add_remove_limiter() {
        let ctx = &mut sui::tx_context::dummy();
        let (policy, cap) = test::get_policy(ctx);

        // adding limiter - confirmation required
        limiter::add_for(&mut policy, &cap, utf8(b"action"), 100, ctx);
        {
            let request = cl::new_request(utf8(b"action"), 100, none(), none(), ctx);
            limiter::verify(&policy, &mut request, ctx);
            cl::confirm_request(&mut policy, request, ctx);
        };

        // limiter removed - no confirmation required
        limiter::remove_for(&mut policy, &cap, utf8(b"action"), ctx);
        {
            let request = cl::new_request(utf8(b"action"), 100, none(), none(), ctx);
            cl::confirm_request(&mut policy, request, ctx);
        };

        // adding again to make sure the config was removed and can be re-added.
        limiter::add_for(&mut policy, &cap, utf8(b"action"), 100, ctx);
        {
            let request = cl::new_request(utf8(b"action"), 100, none(), none(), ctx);
            limiter::verify(&policy, &mut request, ctx);
            cl::confirm_request(&mut policy, request, ctx);
        };

        test::return_policy(policy, cap);
    }

    #[test, expected_failure(abort_code = examples::limiter_rule::ELimitExceeded)]
    // Scenario: add a limiter rule for 100 tokens per operation, verify that
    // the request with 101 tokens aborts with `ELimitExceeded`
    fun add_limiter_limit_exceeded_fail() {
        let ctx = &mut sui::tx_context::dummy();
        let (policy, cap) = test::get_policy(ctx);

        limiter::add_for(&mut policy, &cap, utf8(b"action"), 100, ctx);

        let request = cl::new_request(utf8(b"action"), 101, none(), none(), ctx);
        limiter::verify(&policy, &mut request, ctx);

        abort 1337
    }
}