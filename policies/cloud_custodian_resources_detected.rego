package compliance_framework.cloud_custodian_resources_detected

import rego.v1

violation_id := "cloud_custodian_resource_non_compliant"

risk_templates := [{
	"name": "Cloud Custodian resource policy non-compliance",
	"title": "Cloud resource {{ .resource_type }}/{{ .resource_name }} may be non-compliant",
	"statement": "Cloud Custodian reported resource {{ .resource_name }} of type {{ .resource_type }} as non-compliant with one or more configured cloud policy checks. The resource may expose the organization to misconfiguration, compliance, or security risk until the failing policy condition is remediated.",
	"likelihood_hint": "moderate",
	"impact_hint": "high",
	"violation_ids": [violation_id],
	"dedupe_label_keys": ["resource_type", "resource_id"],
	"label_schema": [
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
	],
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
}]

_check := object.get(input, "check", {})
_resource := object.get(input, "resource", {})
_assessment := object.get(input, "assessment", {})
_execution := object.get(input, "execution", {})

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

check_name := _default_string(object.get(_check, "name", ""), "unknown-check")

resource_type := _default_string(object.get(_resource, "type", object.get(_check, "resource", "")), "unknown-resource-type")

resource_id := _default_string(object.get(_resource, "id", ""), "unknown-resource-id")

_last_segment(value, separator) := segment if {
	parts := [part | some part in split(value, separator); part != ""]
	count(parts) > 1
	segment := parts[count(parts) - 1]
}

resource_name := _last_segment(resource_id, "/") if {
	_last_segment(resource_id, "/") != ""
}

resource_name := _last_segment(resource_id, ":") if {
	not _last_segment(resource_id, "/")
	_last_segment(resource_id, ":") != ""
}

resource_name := resource_id if {
	not _last_segment(resource_id, "/")
	not _last_segment(resource_id, ":")
}

resource_ref := sprintf("%s/%s", [resource_type, resource_name])

provider := _default_string(object.get(_resource, "provider", object.get(_check, "provider", "")), "unknown-provider")

account_id := _default_string(object.get(_resource, "account_id", ""), "")

region := _default_string(object.get(_resource, "region", ""), "")

assessment_status := _default_string(object.get(_assessment, "status", ""), "unknown-assessment-status")

assessment_matched := object.get(_assessment, "matched", false)

inventory_status := _default_string(object.get(_assessment, "inventory_status", ""), "unknown-inventory-status")

execution_status := _default_string(object.get(_execution, "status", ""), "unknown-execution-status")

execution_error := _default_string(object.get(_execution, "error", ""), "")

execution_errors := object.get(_execution, "errors", [])

has_execution_error if {
	execution_status == "error"
}

has_execution_error if {
	execution_error != ""
}

has_execution_error if {
	is_array(execution_errors)
	count(execution_errors) > 0
}

_base_labels := {
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

violation[{"id": violation_id, "remarks": msg}] if {
	assessment_status == "non_compliant"
	msg := sprintf("Cloud Custodian check %q marked resource %q as non-compliant (matched=%v, inventory_status=%q).", [check_name, resource_ref, assessment_matched, inventory_status])
}

violation[{"id": violation_id, "remarks": msg}] if {
	has_execution_error
	msg := sprintf("Cloud Custodian check %q failed while evaluating resource %q (execution_status=%q, error=%v, errors=%v).", [check_name, resource_ref, execution_status, execution_error, execution_errors])
}

title := sprintf("Cloud Custodian check %s on resource %s", [check_name, resource_ref])

description := sprintf("Cloud Custodian check %q evaluated resource %q with assessment status %q and execution status %q.", [check_name, resource_ref, assessment_status, execution_status])
