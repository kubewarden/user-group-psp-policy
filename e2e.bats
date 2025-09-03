#!/usr/bin/env bats

@test "RunAsAny should accept empty runAsUser, runAsGroup and supplementalGroups" {
	run kwctl run  --request-path test_data/e2e/empty_security_context_pod.json --settings-path test_data/e2e/settings_run_as_any.json annotated-policy.wasm
	[ "$status" -eq 0 ]
	echo "$output"
	[ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
 }

@test "MustRunAs should reject invalid user ID" {
	run kwctl run  --request-path test_data/e2e/invalid_user_id.json  --settings-path test_data/e2e/settings_must_run_as.json annotated-policy.wasm
	[ "$status" -eq 0 ]
	echo "$output"
	[ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
	[ $(expr "$output" : '.*"message":"User ID outside defined ranges".*') -ne 0 ]
 }
 
@test "MustRunAs should accept valid container user ID without mutating even if pod securityContext is invalid" {
	run kwctl run  --request-path test_data/e2e/pod_user_150.json  --settings-path test_data/e2e/settings_must_run_as_100_200.json annotated-policy.wasm
	[ "$status" -eq 0 ]
	echo "$output"
	[ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
	[ $(expr "$output" : '.*"patchType":"JSONPatch".*') -eq 0 ]
 }

@test "MustRunAs should reject invalid group ID" {
	run kwctl run  --request-path test_data/e2e/invalid_group_id.json  --settings-path test_data/e2e/settings_must_run_as.json annotated-policy.wasm
	[ "$status" -eq 0 ]
	echo "$output"
	[ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
	[ $(expr "$output" : '.*"message":"Group ID is outside defined ranges".*') -ne 0 ]
 }

@test "MustRunAs should reject invalid supplemental group ID" {
	run kwctl run  --request-path test_data/e2e/invalid_supplemental_group_.json  --settings-path test_data/e2e/settings_must_run_as.json annotated-policy.wasm
	[ "$status" -eq 0 ]
	echo "$output"
	[ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
	[ $(expr "$output" : '.*"message":"Group ID is outside defined ranges".*') -ne 0 ]
 }

@test "MustRunAs should patch empty runAsUser, runAsGroup and supplementalGroups" {
	run kwctl run  --request-path test_data/e2e/empty_security_context_pod.json --settings-path test_data/e2e/settings_must_run_as.json annotated-policy.wasm
	[ "$status" -eq 0 ]
	echo "$output"
	[ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
	[ $(expr "$output" : '.*"patchType":"JSONPatch".*') -ne 0 ]
 }
 
@test "MustRunAs should not patch empty runAsUser, runAsGroup and supplementalGroups when policy is configured to validation only" {
	run kwctl run  --request-path test_data/e2e/empty_security_context_pod.json --settings-path test_data/e2e/settings_must_run_as_validate_only.json annotated-policy.wasm
	[ "$status" -eq 0 ]
	echo "$output"
	[ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
	[ $(expr "$output" : '.*"patchType":"JSONPatch".*') -eq 0 ]
 }

@test "MayRunAs should accept empty runAsGroup and supplementalGroups" {
	run kwctl run  --request-path test_data/e2e/empty_security_context_pod.json --settings-path test_data/e2e/settings_may_run_as.json annotated-policy.wasm
	[ "$status" -eq 0 ]
	echo "$output"
	[ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
 }

@test "MayRunAs should reject invalid group ID" {
	run kwctl run  --request-path test_data/e2e/invalid_group_id.json  --settings-path test_data/e2e/settings_may_run_as.json annotated-policy.wasm
	[ "$status" -eq 0 ]
	echo "$output"
	[ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
	[ $(expr "$output" : '.*"message":"Group ID is outside defined ranges".*') -ne 0 ]
 }

@test "MayRunAs should reject invalid supplemental group ID" {
	run kwctl run  --request-path test_data/e2e/invalid_supplemental_group_.json  --settings-path test_data/e2e/settings_may_run_as.json annotated-policy.wasm
	[ "$status" -eq 0 ]
	echo "$output"
	[ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
	[ $(expr "$output" : '.*"message":"Group ID is outside defined ranges".*') -ne 0 ]
 }

@test "MustRunAs should accept valid runAsUser, runAsGroup and supplementalGroups" {
	run kwctl run  --request-path test_data/e2e/valid_security_context.json --settings-path test_data/e2e/settings_must_run_as.json annotated-policy.wasm
	[ "$status" -eq 0 ]
	echo "$output"
	[ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
}

@test "MustRunAsNonRoot should reject 0 as user ID" {
	run kwctl run  --request-path test_data/e2e/zero_as_user_id.json --settings-path test_data/e2e/settings_must_run_as_non_root.json annotated-policy.wasm
	[ "$status" -eq 0 ]
	echo "$output"
	[ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
	[ $(expr "$output" : '.*"message":"Invalid user ID: cannot run container with root ID (0)".*') -ne 0 ]
}

@test "MustRunAsNonRoot should mutate request when runAsUser is not defined" {
	run kwctl run  --request-path test_data/e2e/empty_security_context_pod.json --settings-path test_data/e2e/settings_must_run_as_non_root.json annotated-policy.wasm
	[ "$status" -eq 0 ]
	echo "$output"
	[ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
	[ $(expr "$output" : '.*"patchType":"JSONPatch".*') -ne 0 ]
}

@test "MustRunAsNonRoot should not mutate request when runAsUser is not defined and policy is configured to validate only" {
	run kwctl run  --request-path test_data/e2e/empty_security_context_pod.json --settings-path test_data/e2e/settings_must_run_as_non_root_validate_only.json annotated-policy.wasm
	[ "$status" -eq 0 ]
	echo "$output"
	[ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
	[ $(expr "$output" : '.*"patchType":"JSONPatch".*') -eq 0 ]
}

@test "MustRunAsNonRoot should accept request when user defined is not root" {
	run kwctl run  --request-path test_data/e2e/valid_security_context.json --settings-path test_data/e2e/settings_must_run_as_non_root.json annotated-policy.wasm
	[ "$status" -eq 0 ]
	echo "$output"
	[ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
}

@test "MustRunAs should patch runAsUser, runAsGroup and supplementalGroups when 'overwrite' is true" {
	run kwctl run  --request-path test_data/e2e/valid_security_context.json --settings-path test_data/e2e/settings_must_run_as_overwrite.json annotated-policy.wasm
	[ "$status" -eq 0 ]
	echo "$output"
	[ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
	[ $(expr "$output" : '.*"patchType":"JSONPatch".*') -ne 0 ]
 }
 
@test "MustRunAs should reject invalid container image user ID" {
	run  kwctl run  --request-path test_data/e2e/invalid_container_image_user_id.json  --settings-path test_data/e2e/settings_must_run_as_container_image_user_validation.json annotated-policy.wasm
	[ "$status" -eq 0 ]
	echo "$output"
	[ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
	[ $(expr "$output" : '.*"message":"User ID defined in the container image is outside defined ranges".*') -ne 0 ]

 }

@test "MustRunAs should reject invalid container image group ID" {
	run  kwctl run  --request-path test_data/e2e/invalid_container_image_user_id.json  --settings-path test_data/e2e/settings_must_run_as_container_image_group_validation.json annotated-policy.wasm
	[ "$status" -eq 0 ]
	echo "$output"
	[ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
	[ $(expr "$output" : '.*"message":"Group ID defined in the container image is outside defined ranges".*') -ne 0 ]
 }


@test "Settings should be invalid when container image user validation settings has an non-boolean value" {
	run  kwctl run  --request-path test_data/e2e/invalid_container_image_user_id.json  --settings-path test_data/e2e/settings_invalid_container_image_verification.json annotated-policy.wasm
	[ "$status" -ne 0 ]
	echo "$output"
	[ $(expr "$output" : '.*invalid type: integer `1`, expected a boolean.*') -ne 0 ]

 }

@test "RunAsAny should accept when container image group validation is enabled" {
	run kwctl run  --request-path test_data/e2e/invalid_container_image_user_id.json --settings-path test_data/e2e/settings_run_as_any_and_validate_container.json annotated-policy.wasm
	[ "$status" -eq 0 ]
	echo "$output"
	[ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
 }
 
@test "MustRunAs should fail when 'overwrite' is true and policy is configured to validation only" {
	run kwctl run  --request-path test_data/e2e/valid_security_context.json --settings-path test_data/e2e/settings_must_run_as_overwrite_validate_only.json annotated-policy.wasm
	[ "$status" -ne 0 ]
	echo "$output"
	[ $(expr "$output" : 'Provided settings are not valid: "validate_only cannot be true when overwrite is true"') -eq 0 ]
 }
