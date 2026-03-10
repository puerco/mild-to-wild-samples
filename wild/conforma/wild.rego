package wild

import rego.v1

import data.lib
import data.lib.tekton

# METADATA
# title: All task bundles are trusted
# description: >-
#   Every task in the Tekton PipelineRun provenance must reference a trusted
#   bundle according to the trusted_task_rules configured in rule_data. A pinned
#   task with a known digest behaves deterministically -- it can't lie about what
#   it built because it was pinned before the build ran.
# custom:
#   short_name: all_tasks_trusted
#   failure_msg: Untrusted task found %s
#   solution: >-
#     Ensure all tasks in the pipeline use bundles that are listed in the
#     trusted_task_rules configuration. Update the pipeline to use trusted
#     task bundles or add the task bundle to the trusted_task_rules allowlist.
#   collections:
#   - minimal
deny contains result if {
	some att in lib.pipelinerun_attestations
	tasks := tekton.tasks(att)
	untrusted := tekton.untrusted_task_refs(tasks)
	count(untrusted) > 0

	some task in untrusted
	ref := tekton.task_ref(task)
	bundle_ref := object.get(ref, "bundle", ref.key)
	result := lib.result_helper(rego.metadata.chain(), [bundle_ref])
}
