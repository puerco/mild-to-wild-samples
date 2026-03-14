package mild_test

import rego.v1

import data.lib
import data.mild

# Provenance presence tests

test_provenance_present_v02 if {
	lib.assert_empty(mild.deny) with input.attestations as [_mock_provenance_v02]
		with data.rule_data__ as _rule_data_v02
}

test_provenance_present_v1 if {
	lib.assert_empty(mild.deny) with input.attestations as [_mock_provenance_v1]
		with data.rule_data__ as _rule_data_v1
}

test_provenance_missing if {
	expected := {{
		"code": "mild.provenance_present",
		"msg": "No SLSA provenance attestation found",
	}}
	lib.assert_equal_results(mild.deny, expected) with input.attestations as []
}

# Build type tests

test_build_type_accepted_v1 if {
	lib.assert_empty(mild.deny) with input.attestations as [_mock_provenance_v1]
		with data.rule_data__ as _rule_data_v1
}

test_build_type_accepted_v02 if {
	lib.assert_empty(mild.deny) with input.attestations as [_mock_provenance_v02]
		with data.rule_data__ as _rule_data_v02
}

test_build_type_rejected if {
	bad := {"statement": {
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": {"buildDefinition": {
			"buildType": "https://example.com/unknown-builder",
			"externalParameters": {},
		}},
	}}
	expected := {{
		"code": "mild.build_type_accepted",
		"msg": "Build type https://example.com/unknown-builder is not in the list of accepted build types",
	}}
	lib.assert_equal_results(mild.deny, expected) with input.attestations as [bad]
		with data.rule_data__ as _rule_data_v1
}

# Mock data

_mock_provenance_v02 := {"statement": {
	"predicateType": "https://slsa.dev/provenance/v0.2",
	"predicate": {"buildType": "tekton.dev/v1/PipelineRun"},
}}

_mock_provenance_v1 := {"statement": {
	"predicateType": "https://slsa.dev/provenance/v1",
	"predicate": {"buildDefinition": {
		"buildType": "https://tekton.dev/chains/v2/slsa",
		"externalParameters": {"runSpec": {}},
	}},
}}

_rule_data_v1 := {"allowed_build_types": ["https://tekton.dev/chains/v2/slsa"]}

_rule_data_v02 := {"allowed_build_types": ["tekton.dev/v1/PipelineRun"]}
