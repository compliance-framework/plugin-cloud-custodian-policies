package compliance_framework.cloud_custodian_resources_detected

import rego.v1

violation_id := "cloud_custodian_resource_non_compliant"
execution_violation_id := "cloud_custodian_resource_evaluation_failed"
unsupported_input_violation_id := "cloud_custodian_unsupported_input"
stderr_max_chars := 500

_label_schema := [
	{
		"key": "resource_type",
		"description": "Cloud Custodian resource type such as aws.ec2 or aws.s3",
	},
	{
		"key": "resource_id",
		"description": "Stable resource identifier extracted from the Cloud Custodian resource data",
	},
	{
		"key": "resource_name",
		"description": "Short display name derived from the resource identifier",
	},
	{
		"key": "provider",
		"description": "Cloud provider from the Cloud Custodian resource or check provider field when available",
	},
	{
		"key": "account_id",
		"description": "Cloud account identifier when available in the resource data",
	},
	{
		"key": "region",
		"description": "Cloud region when available in the resource data",
	},
]

risk_templates := [
	{
		"name": "Cloud Custodian resource policy non-compliance",
		"title": "Cloud resource {{ .resource_type }}/{{ .resource_name }} may be non-compliant",
		"statement": "Cloud Custodian reported resource {{ .resource_name }} of type {{ .resource_type }} as non-compliant with one or more configured cloud policy checks. The resource may expose the organization to misconfiguration, compliance, or security risk until the failing policy condition is remediated.",
		"likelihood_hint": "moderate",
		"impact_hint": "high",
		"violation_ids": [violation_id],
		"dedupe_label_keys": ["resource_type", "resource_id"],
		"label_schema": _label_schema,
		"remediation": {
			"title": "Remediate the failing Cloud Custodian policy condition",
			"description": "Review the Cloud Custodian check and update the affected resource configuration so it no longer matches the non-compliant policy condition.",
			"tasks": [
				{"title": "Review the Cloud Custodian check that marked the resource non-compliant"},
				{"title": "Inspect the affected resource configuration and ownership context"},
				{"title": "Apply the required cloud configuration or access-control change"},
				{"title": "Re-run the Cloud Custodian assessment to confirm the resource is compliant"},
			],
		},
	},
	{
		"name": "Cloud Custodian resource evaluation failure",
		"title": "Cloud Custodian could not fully evaluate {{ .resource_type }}/{{ .resource_name }}",
		"statement": "Cloud Custodian failed while evaluating resource {{ .resource_name }} of type {{ .resource_type }}. Because the policy run did not complete successfully, the compliance state of the resource could not be confirmed and requires investigation.",
		"likelihood_hint": "moderate",
		"impact_hint": "moderate",
		"violation_ids": [execution_violation_id],
		"dedupe_label_keys": ["resource_type", "resource_id"],
		"label_schema": _label_schema,
		"remediation": {
			"title": "Investigate and rerun the failing Cloud Custodian evaluation",
			"description": "Review the execution failure details, correct the underlying evaluation problem, and rerun the Cloud Custodian check so the resource can be assessed successfully.",
			"tasks": [
				{"title": "Review the Cloud Custodian execution error and stderr output"},
				{"title": "Fix the policy, credentials, permissions, or API issue causing the evaluation failure"},
				{"title": "Re-run the Cloud Custodian check to confirm the resource can be evaluated successfully"},
			],
		},
	},
	{
		"name": "Cloud Custodian policy received unsupported input",
		"title": "Cloud Custodian policy received unsupported input {{ .source }}/{{ .schema_version }}",
		"statement": "This policy expected Cloud Custodian per-resource input with schema_version v2 and source cloud-custodian, but received source {{ .source }} and schema_version {{ .schema_version }}. The policy input wiring should be corrected before the compliance result is trusted.",
		"likelihood_hint": "low",
		"impact_hint": "moderate",
		"violation_ids": [unsupported_input_violation_id],
		"dedupe_label_keys": ["source", "schema_version"],
		"label_schema": [
			{
				"key": "source",
				"description": "Input source passed to the policy",
			},
			{
				"key": "schema_version",
				"description": "Input schema version passed to the policy",
			},
		],
		"remediation": {
			"title": "Correct the Cloud Custodian policy input wiring",
			"description": "Ensure this policy is evaluated only against the standardized Cloud Custodian per-resource payload.",
			"tasks": [
				{"title": "Confirm the plugin is sending schema_version v2 payloads"},
				{"title": "Confirm the input source label is cloud-custodian"},
				{"title": "Re-run the policy after correcting the upstream payload wiring"},
			],
		},
	},
]

_check := object.get(input, "check", {})
_resource := object.get(input, "resource", {})
_assessment := object.get(input, "assessment", {})
_execution := object.get(input, "execution", {})
_raw_policy := object.get(input, "raw_policy", {})

input_schema_version := _default_string(object.get(input, "schema_version", ""), "unknown-schema-version")

input_source := _default_string(object.get(input, "source", ""), "unknown-source")

_default_string(value, fallback) := result if {
	is_string(value)
	value != ""
	result := value
}

_default_string(value, fallback) := fallback if {
	is_string(value)
	value == ""
}

_default_string(value, fallback) := fallback if {
	not is_string(value)
}

_safe_stderr(value) := result if {
	first_line := split(value, "\n")[0]
	without_control_chars := regex.replace(first_line, "[[:cntrl:]]+", " ")
	without_authorization := regex.replace(without_control_chars, "(?i)authorization[[:space:]]*:[[:space:]]*.*", "Authorization: <redacted>")
	without_secret_values := regex.replace(without_authorization, "(?i)(password|token|secret|access[_-]?key)([[:space:]]*[:=][[:space:]]*)[^[:space:]]+", "$1$2<redacted>")
	result := _truncate_error_detail(without_secret_values)
}

_truncate_error_detail(value) := value if {
	count(value) <= stderr_max_chars
}

_truncate_error_detail(value) := sprintf("%s...", [substring(value, 0, stderr_max_chars)]) if {
	count(value) > stderr_max_chars
}

check_name := _default_string(object.get(_check, "name", ""), "unknown-check")

resource_type := _default_string(object.get(_resource, "type", object.get(_check, "resource", "")), "unknown-resource-type")

resource_id := _default_string(object.get(_resource, "id", ""), "unknown-resource-id")

_last_segment(value, separator) := segment if {
	contains(value, separator)
	parts := [part | some part in split(value, separator); part != ""]
	count(parts) > 0
	segment := parts[count(parts) - 1]
}

_resource_name_from_slash := value if {
	value := _last_segment(resource_id, "/")
} else := ""

_resource_name_from_colon := value if {
	value := _last_segment(resource_id, ":")
} else := ""

resource_name := _resource_name_from_slash if {
	_resource_name_from_slash != ""
}

resource_name := _resource_name_from_colon if {
	_resource_name_from_slash == ""
	_resource_name_from_colon != ""
}

resource_name := resource_id if {
	_resource_name_from_slash == ""
	_resource_name_from_colon == ""
}

resource_ref := sprintf("%s/%s", [resource_type, resource_name])

provider := _default_string(object.get(_resource, "provider", object.get(_check, "provider", "")), "unknown-provider")

account_id := _default_string(object.get(_resource, "account_id", ""), "")

region := _default_string(object.get(_resource, "region", ""), "")

assessment_status := _default_string(object.get(_assessment, "status", ""), "unknown-assessment-status")

assessment_matched := object.get(_assessment, "matched", false)

inventory_status := _default_string(object.get(_assessment, "inventory_status", ""), "unknown-inventory-status")

execution_status := _default_string(object.get(_execution, "status", ""), "unknown-execution-status")

execution_exit_code := object.get(_execution, "exit_code", "unknown-exit-code")

execution_error := _default_string(object.get(_execution, "error", ""), "")

execution_stderr := _safe_stderr(_default_string(object.get(_execution, "stderr", ""), ""))

execution_errors := object.get(_execution, "errors", [])

execution_error_messages_from_array := messages if {
	is_array(execution_errors)
	messages := [msg |
		some msg in execution_errors
		is_string(msg)
		msg != ""
	]
	count(messages) > 0
} else := []

execution_error_messages := execution_error_messages_from_array if {
	count(execution_error_messages_from_array) > 0
} else := [execution_error] if {
	execution_error != ""
} else := [execution_stderr] if {
	execution_stderr != ""
} else := []

execution_error_details := concat("; ", execution_error_messages) if {
	count(execution_error_messages) > 0
} else := "no detailed error message was provided"

raw_policy_name := _default_string(object.get(_raw_policy, "name", ""), check_name)

raw_policy_resource := _default_string(object.get(_raw_policy, "resource", ""), resource_type)

non_compliance_message := _default_string(object.get(_raw_policy, "non_compliance_message", ""), "")

matched_resource_count := object.get(_assessment, "matched_resource_count", "unknown")

supported_input if {
	input_schema_version == "v2"
	input_source == "cloud-custodian"
}

has_execution_error if {
	execution_status == "error"
}

has_execution_error if {
	execution_error != ""
}

has_execution_error if {
	count(execution_error_messages_from_array) > 0
}

_base_labels := {
	"schema_version": input_schema_version,
	"source": input_source,
	"resource_type": resource_type,
	"resource_id": resource_id,
	"resource_name": resource_name,
}

_provider_label := {"provider": provider} if {
	provider != "unknown-provider"
}

_provider_label := {} if {
	provider == "unknown-provider"
}

_account_label := {"account_id": account_id} if {
	account_id != ""
}

_account_label := {} if {
	account_id == ""
}

_region_label := {"region": region} if {
	region != ""
}

_region_label := {} if {
	region == ""
}

labels := object.union(
	object.union(
		object.union(_base_labels, _provider_label),
		_account_label,
	),
	_region_label,
)

is_non_compliant if {
	supported_input
	assessment_status == "non_compliant"
}

is_compliant if {
	supported_input
	assessment_status == "compliant"
}

is_execution_failed if {
	supported_input
	has_execution_error
}

non_compliant_remark := sprintf("Resource %q failed Cloud Custodian policy %q (resource=%q); the resource was found by this policy run (matched=%v, inventory_status=%q, matched_resource_count=%v).", [resource_ref, raw_policy_name, raw_policy_resource, assessment_matched, inventory_status, matched_resource_count]) if {
	is_non_compliant
}

execution_error_remark := sprintf("Cloud Custodian policy %q ran with errors while evaluating resource %q (execution_status=%q, exit_code=%v). Errors: %s.", [raw_policy_name, resource_ref, execution_status, execution_exit_code, execution_error_details]) if {
	is_execution_failed
}

unsupported_input_remark := sprintf("Unsupported Cloud Custodian policy input: expected source=%q schema_version=%q but received source=%q schema_version=%q.", ["cloud-custodian", "v2", input_source, input_schema_version]) if {
	not supported_input
}

violation[{"id": violation_id, "remarks": non_compliant_remark}] if {
	is_non_compliant
}

violation[{"id": execution_violation_id, "remarks": execution_error_remark}] if {
	is_execution_failed
}

violation[{"id": unsupported_input_violation_id, "remarks": unsupported_input_remark}] if {
	not supported_input
}

remarks := sprintf("%s %s", [non_compliant_remark, execution_error_remark]) if {
	is_non_compliant
	is_execution_failed
}

remarks := non_compliant_remark if {
	is_non_compliant
	not is_execution_failed
}

remarks := execution_error_remark if {
	not is_non_compliant
	is_execution_failed
}

remarks := unsupported_input_remark if {
	not supported_input
}

title := "Cloud Custodian policy received unsupported input" if {
	not supported_input
}

title := sprintf("Cloud Custodian check %s on resource %s", [check_name, resource_ref]) if {
	supported_input
}

description := sprintf("Cloud Custodian policy expected source=%q schema_version=%q but received source=%q schema_version=%q.", ["cloud-custodian", "v2", input_source, input_schema_version]) if {
	not supported_input
}

description_base := sprintf("Cloud Custodian check %q failed for resource %q.", [check_name, resource_ref]) if {
	supported_input
	is_non_compliant
}

description_base := sprintf("Cloud Custodian check %q could not evaluate resource %q.", [check_name, resource_ref]) if {
	supported_input
	not is_non_compliant
	is_execution_failed
}

description_base := sprintf("Cloud Custodian check %q passed for resource %q.", [check_name, resource_ref]) if {
	supported_input
	is_compliant
	not is_execution_failed
}

description_base := sprintf("Cloud Custodian check %q evaluated resource %q.", [check_name, resource_ref]) if {
	supported_input
	not is_non_compliant
	not is_compliant
	not is_execution_failed
}

has_non_compliance_message if {
	is_non_compliant
	non_compliance_message != ""
}

description_execution_error := sprintf("Execution errors: %s.", [execution_error_details]) if {
	is_execution_failed
}

description := sprintf("%s %s %s", [description_base, non_compliance_message, description_execution_error]) if {
	supported_input
	has_non_compliance_message
	is_execution_failed
}

description := sprintf("%s %s", [description_base, non_compliance_message]) if {
	supported_input
	has_non_compliance_message
	not is_execution_failed
}

description := sprintf("%s %s", [description_base, description_execution_error]) if {
	supported_input
	not has_non_compliance_message
	is_execution_failed
}

description := description_base if {
	supported_input
	not has_non_compliance_message
	not is_execution_failed
}
