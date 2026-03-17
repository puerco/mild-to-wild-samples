package wild_test

import rego.v1

import data.lib
import data.wild

# PipelineRun provenance: trusted tasks pass

test_pipelinerun_trusted_tasks_pass if {
	trusted_task_rules := {
		"allow": [{"name": "Allow Konflux", "pattern": "oci://quay.io/konflux-ci/tekton-catalog/*"}],
		"deny": [],
	}
	lib.assert_empty(wild.warn) with input.attestations as [_mock_pipelinerun_trusted]
		with data.trusted_task_rules as trusted_task_rules
}

# PipelineRun provenance: untrusted task warns

test_pipelinerun_untrusted_task_warns if {
	trusted_task_rules := {
		"allow": [{"name": "Allow Konflux", "pattern": "oci://quay.io/konflux-ci/tekton-catalog/*"}],
		"deny": [],
	}
	expected := {{
		"code": "wild.all_tasks_trusted",
		"msg": "Untrusted task found: oci://quay.io/untrusted/task-bad@sha256:abc123",
	}}
	lib.assert_equal_results(wild.warn, expected) with input.attestations as [_mock_pipelinerun_untrusted]
		with data.trusted_task_rules as trusted_task_rules
}

# TaskRun provenance: trusted git resolver ref passes

test_taskrun_trusted_ref_pass if {
	trusted_task_refs := [{"uri": "git+https://github.com/arewm/mild-to-wild-samples", "digest": {"sha1": "abc123"}}]
	lib.assert_empty(wild.warn) with input.attestations as [_mock_taskrun_v1("git+https://github.com/arewm/mild-to-wild-samples", "abc123")]
		with data.rule_data_custom as {"trusted_task_refs": trusted_task_refs}
}

# TaskRun provenance: untrusted git resolver ref warns

test_taskrun_untrusted_ref_warns if {
	trusted_task_refs := [{"uri": "git+https://github.com/arewm/mild-to-wild-samples", "digest": {"sha1": "abc123"}}]
	expected := {{
		"code": "wild.all_tasks_trusted",
		"msg": "Untrusted task found: git+https://github.com/other/repo",
	}}
	lib.assert_equal_results(wild.warn, expected) with input.attestations as [_mock_taskrun_v1("git+https://github.com/other/repo", "def456")]
		with data.rule_data_custom as {"trusted_task_refs": trusted_task_refs}
}

# TaskRun provenance: wrong digest warns

test_taskrun_wrong_digest_warns if {
	trusted_task_refs := [{"uri": "git+https://github.com/arewm/mild-to-wild-samples", "digest": {"sha1": "abc123"}}]
	expected := {{
		"code": "wild.all_tasks_trusted",
		"msg": "Untrusted task found: git+https://github.com/arewm/mild-to-wild-samples",
	}}
	lib.assert_equal_results(wild.warn, expected) with input.attestations as [_mock_taskrun_v1("git+https://github.com/arewm/mild-to-wild-samples", "wrong")]
		with data.rule_data_custom as {"trusted_task_refs": trusted_task_refs}
}

# No Tekton provenance: warns about missing task refs

test_no_tekton_provenance_warns if {
	non_tekton := {"statement": {
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": {"buildDefinition": {
			"buildType": "https://github.com/actions/runner",
			"externalParameters": {},
			"resolvedDependencies": [],
		}},
	}}
	expected := {{
		"code": "wild.pipelinerun_provenance_for_trusted_tasks",
		"msg": "No Tekton provenance with task references found -- trusted task verification skipped",
	}}
	lib.assert_equal_results(wild.warn, expected) with input.attestations as [non_tekton]
}

test_no_attestations_warns if {
	expected := {{
		"code": "wild.pipelinerun_provenance_for_trusted_tasks",
		"msg": "No Tekton provenance with task references found -- trusted task verification skipped",
	}}
	lib.assert_equal_results(wild.warn, expected) with input.attestations as []
}

# No warning when TaskRun has task dep (even if untrusted — that's a
# separate warning from all_tasks_trusted)

test_taskrun_with_task_dep_no_missing_warning if {
	trusted_task_refs := [{"uri": "git+https://github.com/other/repo", "digest": {"sha1": "abc"}}]
	warnings := wild.warn with input.attestations as [_mock_taskrun_v1("git+https://github.com/arewm/mild-to-wild-samples", "abc123")]
		with data.rule_data_custom as {"trusted_task_refs": trusted_task_refs}
	codes := {w.code | some w in warnings}
	not "wild.pipelinerun_provenance_for_trusted_tasks" in codes
}

# Mock data

_mock_pipelinerun_trusted := {"statement": {
	"predicateType": "https://slsa.dev/provenance/v0.2",
	"predicate": {
		"buildType": "tekton.dev/v1/PipelineRun",
		"buildConfig": {"tasks": [{
			"name": "build-task",
			"ref": {"name": "buildah", "bundle": "oci://quay.io/konflux-ci/tekton-catalog/task-buildah@sha256:123abc"},
			"invocation": {"parameters": {}},
			"results": [],
		}]},
	},
}}

_mock_pipelinerun_untrusted := {"statement": {
	"predicateType": "https://slsa.dev/provenance/v0.2",
	"predicate": {
		"buildType": "tekton.dev/v1/PipelineRun",
		"buildConfig": {"tasks": [{
			"name": "bad-task",
			"ref": {"name": "bad", "bundle": "oci://quay.io/untrusted/task-bad@sha256:abc123"},
			"invocation": {"parameters": {}},
			"results": [],
		}]},
	},
}}

_mock_taskrun_v1(uri, sha1) := {"statement": {
	"predicateType": "https://slsa.dev/provenance/v1",
	"predicate": {"buildDefinition": {
		"buildType": "https://tekton.dev/chains/v2/slsa",
		"externalParameters": {"runSpec": {"taskSpec": {}}},
		"resolvedDependencies": [{"name": "task", "uri": uri, "digest": {"sha1": sha1}}],
	}},
}}
