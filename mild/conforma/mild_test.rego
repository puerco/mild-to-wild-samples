package mild_test

import rego.v1

import data.lib
import data.mild

# Provenance presence tests

test_provenance_present_v02 if {
	lib.assert_empty(mild.deny) with input.attestations as [_mock_provenance_v02]
}

test_provenance_present_v1 if {
	lib.assert_empty(mild.deny) with input.attestations as [_mock_provenance_v1]
}

test_provenance_missing if {
	expected := {{
		"code": "mild.provenance_present",
		"msg": "No SLSA provenance attestation found",
	}}
	lib.assert_equal_results(mild.deny, expected) with input.attestations as [_mock_vsa_l1]
}

test_provenance_empty if {
	expected := {{
		"code": "mild.provenance_present",
		"msg": "No SLSA provenance attestation found",
	}}
	lib.assert_equal_results(mild.deny, expected) with input.attestations as []
}

# VSA level tests -- include provenance to avoid provenance_present denial

test_vsa_meets_slsa_level_pass if {
	lib.assert_empty(mild.deny) with input.attestations as [_mock_provenance_v02, _mock_vsa_l1]
}

test_vsa_meets_slsa_level_fail if {
	vsa_l0 := {"statement": {
		"predicateType": "https://slsa.dev/verification_summary/v1",
		"predicate": {"verifiedLevels": ["SLSA_BUILD_LEVEL_0"]},
	}}
	expected := {{
		"code": "mild.vsa_meets_slsa_level",
		"msg": "VSA does not meet SLSA Build Level 1",
	}}
	lib.assert_equal_results(mild.deny, expected) with input.attestations as [_mock_provenance_v02, vsa_l0]
}

test_vsa_meets_slsa_level_multiple_levels if {
	vsa := {"statement": {
		"predicateType": "https://slsa.dev/verification_summary/v1",
		"predicate": {"verifiedLevels": [
			"SLSA_BUILD_LEVEL_0",
			"SLSA_BUILD_LEVEL_1",
			"SLSA_BUILD_LEVEL_2",
		]},
	}}
	lib.assert_empty(mild.deny) with input.attestations as [_mock_provenance_v02, vsa]
}

test_vsa_no_vsa_present if {
	# No VSA present should not trigger the vsa_meets_slsa_level rule
	lib.assert_empty(mild.deny) with input.attestations as [_mock_provenance_v02]
}

# Mock data -- inline constant values to avoid cross-package resolution issues

_mock_provenance_v02 := {"statement": {
	"predicateType": "https://slsa.dev/provenance/v0.2",
	"predicate": {"buildType": "tekton.dev/v1/PipelineRun"},
}}

_mock_provenance_v1 := {"statement": {
	"predicateType": "https://slsa.dev/provenance/v1",
	"predicate": {
		"buildDefinition": {
			"buildType": "https://tekton.dev/chains/v2/slsa-tekton",
			"externalParameters": {"runSpec": {"pipelineSpec": {}}},
		},
		"runDetails": {"builder": {"id": "https://tekton.dev/chains/v2"}},
	},
}}

_mock_vsa_l1 := {"statement": {
	"predicateType": "https://slsa.dev/verification_summary/v1",
	"predicate": {"verifiedLevels": ["SLSA_BUILD_LEVEL_1"]},
}}
