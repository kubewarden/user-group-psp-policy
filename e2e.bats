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

@test "MustRunAsNonRoot should accept request when user defined is not root" {
	run kwctl run  --request-path test_data/e2e/valid_security_context.json --settings-path test_data/e2e/settings_must_run_as_non_root.json annotated-policy.wasm
	[ "$status" -eq 0 ]
	echo "$output"
	[ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
}
