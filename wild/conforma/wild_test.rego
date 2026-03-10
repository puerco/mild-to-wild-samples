package wild_test

import rego.v1

import data.lib
import data.wild

test_all_tasks_trusted_pass if {
	attestations := [_mock_pipelinerun_with_trusted_task]
	trusted_task_rules := {
		"allow": [{
			"name": "Allow all Konflux tasks",
			"pattern": "oci://quay.io/konflux-ci/tekton-catalog/*",
		}],
		"deny": [],
	}
	lib.assert_empty(wild.deny) with input.attestations as attestations
		with data.trusted_task_rules as trusted_task_rules
}

test_all_tasks_trusted_fail if {
	attestations := [_mock_pipelinerun_with_untrusted_task]
	trusted_task_rules := {
		"allow": [{
			"name": "Allow Konflux tasks",
			"pattern": "oci://quay.io/konflux-ci/tekton-catalog/*",
		}],
		"deny": [],
	}
	expected := {{
		"code": "wild.all_tasks_trusted",
		"msg": "Untrusted task found oci://quay.io/untrusted/task-bad@sha256:abc123",
	}}
	lib.assert_equal_results(wild.deny, expected) with input.attestations as attestations
		with data.trusted_task_rules as trusted_task_rules
}

test_all_tasks_trusted_deny_rule if {
	attestations := [_mock_pipelinerun_with_denied_task]
	trusted_task_rules := {
		"allow": [{
			"name": "Allow all tasks",
			"pattern": "oci://*",
		}],
		"deny": [{
			"name": "Deny deprecated task",
			"pattern": "oci://quay.io/deprecated/*",
			"message": "This task is deprecated",
		}],
	}
	expected := {{
		"code": "wild.all_tasks_trusted",
		"msg": "Untrusted task found oci://quay.io/deprecated/old-task@sha256:def456",
	}}
	lib.assert_equal_results(wild.deny, expected) with input.attestations as attestations
		with data.trusted_task_rules as trusted_task_rules
}

test_all_tasks_trusted_no_tasks if {
	attestations := [_mock_pipelinerun_no_tasks]
	lib.assert_empty(wild.deny) with input.attestations as attestations
}

_mock_pipelinerun_with_trusted_task := {"statement": {
	"predicateType": "https://slsa.dev/provenance/v0.2",
	"predicate": {
		"buildType": "tekton.dev/v1/PipelineRun",
		"buildConfig": {"tasks": [{
			"name": "build-task",
			"ref": {
				"name": "buildah",
				"bundle": "oci://quay.io/konflux-ci/tekton-catalog/task-buildah@sha256:123abc",
			},
			"invocation": {"parameters": {}},
			"results": [],
		}]},
	},
}}

_mock_pipelinerun_with_untrusted_task := {"statement": {
	"predicateType": "https://slsa.dev/provenance/v0.2",
	"predicate": {
		"buildType": "tekton.dev/v1/PipelineRun",
		"buildConfig": {"tasks": [{
			"name": "bad-task",
			"ref": {
				"name": "bad",
				"bundle": "oci://quay.io/untrusted/task-bad@sha256:abc123",
			},
			"invocation": {"parameters": {}},
			"results": [],
		}]},
	},
}}

_mock_pipelinerun_with_denied_task := {"statement": {
	"predicateType": "https://slsa.dev/provenance/v0.2",
	"predicate": {
		"buildType": "tekton.dev/v1/PipelineRun",
		"buildConfig": {"tasks": [{
			"name": "old-task",
			"ref": {
				"name": "old",
				"bundle": "oci://quay.io/deprecated/old-task@sha256:def456",
			},
			"invocation": {"parameters": {}},
			"results": [],
		}]},
	},
}}

_mock_pipelinerun_no_tasks := {"statement": {
	"predicateType": "https://slsa.dev/provenance/v0.2",
	"predicate": {
		"buildType": "tekton.dev/v1/PipelineRun",
		"buildConfig": {"tasks": []},
	},
}}
