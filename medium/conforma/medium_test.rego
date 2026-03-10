package medium_test

import rego.v1

import data.lib
import data.medium

# Branch check tests -- include SBOM to avoid sbom_present denial

test_trusted_source_branch_pass if {
	lib.assert_empty(medium.deny) with input.attestations as [
		_mock_provenance("refs/heads/main"),
		_mock_sbom,
	]
}

test_trusted_source_branch_fail_different_branch if {
	expected := {{
		"code": "medium.trusted_source_branch",
		"msg": "Build not from trusted branch, found refs/heads/dev",
	}}
	lib.assert_equal_results(medium.deny, expected) with input.attestations as [
		_mock_provenance("refs/heads/dev"),
		_mock_sbom,
	]
}

test_trusted_source_branch_fail_tag if {
	expected := {{
		"code": "medium.trusted_source_branch",
		"msg": "Build not from trusted branch, found refs/tags/v1.0.0",
	}}
	lib.assert_equal_results(medium.deny, expected) with input.attestations as [
		_mock_provenance("refs/tags/v1.0.0"),
		_mock_sbom,
	]
}

# SBOM check tests -- include valid provenance to avoid branch denial

test_sbom_present_pass if {
	lib.assert_empty(medium.deny) with input.attestations as [
		_mock_provenance("refs/heads/main"),
		_mock_sbom,
	]
}

test_sbom_present_fail if {
	expected := {{
		"code": "medium.sbom_present",
		"msg": "No CycloneDX SBOM found",
	}}
	lib.assert_equal_results(medium.deny, expected) with input.attestations as [
		_mock_provenance("refs/heads/main"),
	]
}

# Mock data

_mock_provenance(git_ref) := {"statement": {
	"predicateType": "https://slsa.dev/provenance/v1",
	"predicate": {
		"buildDefinition": {
			"buildType": "https://tekton.dev/chains/v2/slsa-tekton",
			"externalParameters": {
				"git": {"ref": git_ref},
				"runSpec": {"pipelineSpec": {}},
			},
		},
		"runDetails": {
			"builder": {"id": "https://tekton.dev/chains/v2"},
			"metadata": {"buildFinishedOn": "2024-01-01T00:00:00Z"},
		},
	},
}}

_mock_sbom := {"statement": {
	"predicateType": "https://cyclonedx.org/bom",
	"predicate": {"bomFormat": "CycloneDX"},
}}
