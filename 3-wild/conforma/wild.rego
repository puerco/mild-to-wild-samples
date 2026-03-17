package wild

import rego.v1

import data.lib
import data.lib.tekton

# METADATA
# title: All task bundles are trusted
# description: >-
#   Every task in the Tekton provenance must reference a trusted task.
#   For PipelineRun provenance, checks task bundle refs against
#   trusted_task_rules. For TaskRun provenance (SLSA v1), checks the
#   resolved task dependency against trusted_task_refs rule data.
#   A pinned task with a known digest behaves deterministically -- it
#   can't lie about what it built because it was pinned before the build
#   ran.
# custom:
#   short_name: all_tasks_trusted
#   failure_msg: "Untrusted task found: %s"
#   solution: >-
#     Ensure all tasks in the pipeline use references that are listed
#     in the trusted_task_rules or trusted_task_refs configuration.
#   collections:
#   - minimal

# PipelineRun provenance: check task bundles via upstream helpers
warn contains result if {
	some att in lib.pipelinerun_attestations
	tasks := tekton.tasks(att)

	# Collect bundle refs and fetch manifests for version constraint checking
	bundle_refs := {ref |
		some task in tasks
		ref := tekton.task_ref(task).bundle
		ref != ""
	}
	manifests := ec.oci.image_manifests(bundle_refs)

	untrusted := tekton.untrusted_task_refs(tasks, manifests)
	count(untrusted) > 0

	some task in untrusted
	ref := tekton.task_ref(task)
	bundle_ref := object.get(ref, "bundle", ref.key)
	result := lib.result_helper(rego.metadata.chain(), [bundle_ref])
}

# METADATA
# title: All task bundles are trusted
# description: >-
#   For TaskRun provenance (SLSA v1), checks the resolved task
#   dependency against trusted_task_refs rule data.
# custom:
#   short_name: all_tasks_trusted
#   failure_msg: "Untrusted task found: %s"
#   solution: >-
#     Ensure the task reference is listed in the trusted_task_refs
#     configuration.
#   collections:
#   - minimal
warn contains result if {
	some att in lib.slsa_provenance_attestations
	att.statement.predicateType == "https://slsa.dev/provenance/v1"

	# Only apply to TaskRun provenance (no pipelineRef/pipelineSpec)
	runSpec := att.statement.predicate.buildDefinition.externalParameters.runSpec
	not runSpec.pipelineRef
	not runSpec.pipelineSpec

	some dep in att.statement.predicate.buildDefinition.resolvedDependencies
	dep.name == "task"

	trusted := lib.rule_data("trusted_task_refs")
	not _is_trusted_task_ref(dep, trusted)

	result := lib.result_helper(rego.metadata.chain(), [dep.uri])
}

# A resolved dependency matches a trusted ref if the URI prefix matches
# and all specified digest algorithms match.
_is_trusted_task_ref(dep, trusted) if {
	some ref in trusted
	startswith(dep.uri, ref.uri)
	every algo, value in ref.digest {
		dep.digest[algo] == value
	}
}

# METADATA
# title: Tekton provenance present for trusted task verification
# description: >-
#   Tekton provenance with task references must be present for trusted
#   task verification to be meaningful. Without it, task trust cannot
#   be established and SLSA Build Level 3 cannot be achieved.
# custom:
#   short_name: pipelinerun_provenance_for_trusted_tasks
#   failure_msg: No Tekton provenance with task references found -- trusted task verification skipped
#   solution: >-
#     Build the image using Tekton so that Chains generates provenance
#     containing task references.
#   collections:
#   - minimal
warn contains result if {
	# No PipelineRun attestations
	count(lib.pipelinerun_attestations) == 0

	# And no TaskRun v1 attestations with a task resolved dependency
	count(_taskrun_task_deps) == 0

	result := lib.result_helper(rego.metadata.chain(), [])
}

_taskrun_task_deps := [dep |
	some att in lib.slsa_provenance_attestations
	att.statement.predicateType == "https://slsa.dev/provenance/v1"
	some dep in att.statement.predicate.buildDefinition.resolvedDependencies
	dep.name == "task"
]
