package compliance_framework.cloud_custodian_resources_detected_test

import data.compliance_framework.cloud_custodian_resources_detected
import rego.v1

_payload(status) := {
	"schema_version": "v2",
	"source": "cloud-custodian",
	"check": {
		"name": "ec2-public-ip-check",
		"resource": "aws.ec2",
		"provider": "aws",
		"index": 0,
	},
	"resource": {
		"id": "i-123",
		"type": "aws.ec2",
		"provider": "aws",
		"account_id": "123456789012",
		"region": "us-east-1",
		"identity_fields": {"InstanceId": "i-123"},
		"data": {"InstanceId": "i-123"},
	},
	"assessment": {
		"status": status,
		"matched": status == "non_compliant",
		"inventory_status": "baseline",
		"matched_resource_count": 1,
	},
	"execution": {
		"status": "success",
		"dry_run": true,
		"exit_code": 0,
		"error": "",
	},
	"raw_policy": {
		"name": "ec2-public-ip-check",
		"resource": "aws.ec2",
	},
}

test_non_compliant_resource_produces_one_violation if {
	fixture := _payload("non_compliant")

	violations := cloud_custodian_resources_detected.violation with input as fixture
	count(violations) == 1
	violations[{
		"id": "cloud_custodian_resource_non_compliant",
		"remarks": "Resource \"aws.ec2/i-123\" failed Cloud Custodian policy \"ec2-public-ip-check\" (resource=\"aws.ec2\"); the resource was found by this policy run (matched=true, inventory_status=\"baseline\", matched_resource_count=1).",
	}]
	cloud_custodian_resources_detected.remarks == "Resource \"aws.ec2/i-123\" failed Cloud Custodian policy \"ec2-public-ip-check\" (resource=\"aws.ec2\"); the resource was found by this policy run (matched=true, inventory_status=\"baseline\", matched_resource_count=1)." with input as fixture
}

test_compliant_resource_produces_no_violation if {
	fixture := _payload("compliant")

	count(cloud_custodian_resources_detected.violation) == 0 with input as fixture
}

test_successful_compliant_resource_with_stderr_logs_produces_no_violation if {
	fixture := object.union_n([
		_payload("compliant"),
		{"execution": {
			"status": "success",
			"dry_run": true,
			"exit_code": 0,
			"error": "",
			"errors": [],
			"stderr": "2026-04-28 10:22:50,848: custodian.policy:INFO policy:iam-role-missing-cost-code-tags resource:aws.iam-role region:us-east-1 count:0 time:0.00\n",
		}},
	])

	count(cloud_custodian_resources_detected.violation) == 0 with input as fixture
	not cloud_custodian_resources_detected.remarks with input as fixture
}

test_unsupported_input_produces_dedicated_violation if {
	fixture := {
		"schema_version": "v1",
		"source": "legacy-cloud-custodian",
		"assessment": {"status": "non_compliant"},
		"execution": {"status": "error", "error": "boom", "errors": ["boom"]},
	}

	violations := cloud_custodian_resources_detected.violation with input as fixture
	count(violations) == 1
	violations[{
		"id": "cloud_custodian_unsupported_input",
		"remarks": "Unsupported Cloud Custodian policy input: expected source=\"cloud-custodian\" schema_version=\"v2\" but received source=\"legacy-cloud-custodian\" schema_version=\"v1\".",
	}]
	cloud_custodian_resources_detected.remarks == "Unsupported Cloud Custodian policy input: expected source=\"cloud-custodian\" schema_version=\"v2\" but received source=\"legacy-cloud-custodian\" schema_version=\"v1\"." with input as fixture
	cloud_custodian_resources_detected.title == "Cloud Custodian policy received unsupported input" with input as fixture
	cloud_custodian_resources_detected.description == "Cloud Custodian policy expected source=\"cloud-custodian\" schema_version=\"v2\" but received source=\"legacy-cloud-custodian\" schema_version=\"v1\"." with input as fixture
}

test_execution_failure_produces_violation_even_when_assessment_is_compliant if {
	fixture := object.union_n([
		_payload("compliant"),
		{"execution": {
			"status": "error",
			"dry_run": true,
			"exit_code": 1,
			"error": "custodian execution failed",
			"errors": ["custodian execution failed"],
		}},
	])

	violations := cloud_custodian_resources_detected.violation with input as fixture
	count(violations) == 1
	count([1 |
		violations[{"id": "cloud_custodian_resource_evaluation_failed", "remarks": remarks}]
		contains(remarks, "Cloud Custodian policy \"ec2-public-ip-check\" ran with errors while evaluating resource \"aws.ec2/i-123\"")
		contains(remarks, "execution_status=\"error\"")
		contains(remarks, "exit_code=1")
		contains(remarks, "Errors: custodian execution failed.")
		contains(remarks, "custodian execution failed")
	]) == 1
	contains(cloud_custodian_resources_detected.remarks, "Cloud Custodian policy \"ec2-public-ip-check\" ran with errors while evaluating resource \"aws.ec2/i-123\"") with input as fixture
	contains(cloud_custodian_resources_detected.remarks, "Errors: custodian execution failed.") with input as fixture
	cloud_custodian_resources_detected.description == "Cloud Custodian check \"ec2-public-ip-check\" could not evaluate resource \"aws.ec2/i-123\". Execution errors: custodian execution failed." with input as fixture
}

test_execution_failure_and_non_compliant_assessment_produce_two_violations if {
	fixture := object.union_n([
		_payload("non_compliant"),
		{"execution": {
			"status": "error",
			"dry_run": true,
			"exit_code": 1,
			"error": "custodian execution failed",
			"errors": ["custodian execution failed"],
		}},
	])

	violations := cloud_custodian_resources_detected.violation with input as fixture
	count(violations) == 2
	violations[{
		"id": "cloud_custodian_resource_non_compliant",
		"remarks": "Resource \"aws.ec2/i-123\" failed Cloud Custodian policy \"ec2-public-ip-check\" (resource=\"aws.ec2\"); the resource was found by this policy run (matched=true, inventory_status=\"baseline\", matched_resource_count=1).",
	}]
	count([1 |
		violations[{"id": "cloud_custodian_resource_evaluation_failed", "remarks": remarks}]
		contains(remarks, "Cloud Custodian policy \"ec2-public-ip-check\" ran with errors while evaluating resource \"aws.ec2/i-123\"")
		contains(remarks, "execution_status=\"error\"")
		contains(remarks, "exit_code=1")
		contains(remarks, "Errors: custodian execution failed.")
		contains(remarks, "custodian execution failed")
	]) == 1
	contains(cloud_custodian_resources_detected.remarks, "Resource \"aws.ec2/i-123\" failed Cloud Custodian policy \"ec2-public-ip-check\"") with input as fixture
	contains(cloud_custodian_resources_detected.remarks, "Cloud Custodian policy \"ec2-public-ip-check\" ran with errors while evaluating resource \"aws.ec2/i-123\"") with input as fixture
	cloud_custodian_resources_detected.description == "Cloud Custodian check \"ec2-public-ip-check\" failed for resource \"aws.ec2/i-123\". Execution errors: custodian execution failed." with input as fixture
}

test_execution_failure_remark_uses_error_when_errors_array_is_empty if {
	fixture := object.union_n([
		_payload("compliant"),
		{"execution": {
			"status": "error",
			"dry_run": true,
			"exit_code": 2,
			"error": "policy timed out",
			"errors": [],
		}},
	])

	violations := cloud_custodian_resources_detected.violation with input as fixture
	count(violations) == 1
	violations[{
		"id": "cloud_custodian_resource_evaluation_failed",
		"remarks": "Cloud Custodian policy \"ec2-public-ip-check\" ran with errors while evaluating resource \"aws.ec2/i-123\" (execution_status=\"error\", exit_code=2). Errors: policy timed out.",
	}]
}

test_execution_failure_remark_uses_stderr_when_error_details_are_empty if {
	fixture := object.union_n([
		_payload("compliant"),
		{"execution": {
			"status": "error",
			"dry_run": true,
			"exit_code": 3,
			"error": "",
			"errors": [],
			"stderr": "access denied reading EC2 instances\nsecond log line should not be included",
		}},
	])

	violations := cloud_custodian_resources_detected.violation with input as fixture
	count(violations) == 1
	violations[{
		"id": "cloud_custodian_resource_evaluation_failed",
		"remarks": "Cloud Custodian policy \"ec2-public-ip-check\" ran with errors while evaluating resource \"aws.ec2/i-123\" (execution_status=\"error\", exit_code=3). Errors: access denied reading EC2 instances.",
	}]
}

test_execution_failure_remark_redacts_sensitive_stderr_values if {
	fixture := object.union_n([
		_payload("compliant"),
		{"execution": {
			"status": "error",
			"dry_run": true,
			"exit_code": 3,
			"error": "",
			"errors": [],
			"stderr": "Authorization: Bearer secret-token token=abc123 password=hunter2 access_key=AKIAEXAMPLE",
		}},
	])

	violations := cloud_custodian_resources_detected.violation with input as fixture
	count(violations) == 1
	violations[{
		"id": "cloud_custodian_resource_evaluation_failed",
		"remarks": "Cloud Custodian policy \"ec2-public-ip-check\" ran with errors while evaluating resource \"aws.ec2/i-123\" (execution_status=\"error\", exit_code=3). Errors: Authorization: <redacted> token=<redacted> password=<redacted> access_key=<redacted>.",
	}]
}

test_execution_failure_remark_truncates_long_stderr if {
	long_stderr := sprintf("%sDO_NOT_INCLUDE", [concat("", ["x" | some i in numbers.range(1, 520)])])
	fixture := object.union_n([
		_payload("compliant"),
		{"execution": {
			"status": "error",
			"dry_run": true,
			"exit_code": 3,
			"error": "",
			"errors": [],
			"stderr": long_stderr,
		}},
	])

	remarks := cloud_custodian_resources_detected.remarks with input as fixture
	contains(remarks, sprintf("Errors: %s...", [concat("", ["x" | some i in numbers.range(1, 500)])]))
	not contains(remarks, "DO_NOT_INCLUDE")
}

test_execution_failure_remark_handles_missing_error_details if {
	fixture := object.union_n([
		_payload("compliant"),
		{"execution": {
			"status": "error",
			"dry_run": true,
			"exit_code": 4,
			"error": "",
			"errors": [],
			"stderr": "",
		}},
	])

	violations := cloud_custodian_resources_detected.violation with input as fixture
	count(violations) == 1
	violations[{
		"id": "cloud_custodian_resource_evaluation_failed",
		"remarks": "Cloud Custodian policy \"ec2-public-ip-check\" ran with errors while evaluating resource \"aws.ec2/i-123\" (execution_status=\"error\", exit_code=4). Errors: no detailed error message was provided.",
	}]
}

test_dynamic_title_and_description_use_resource_payload if {
	fixture := _payload("non_compliant")

	cloud_custodian_resources_detected.title == "Cloud Custodian check ec2-public-ip-check on resource aws.ec2/i-123" with input as fixture
	cloud_custodian_resources_detected.description == "Cloud Custodian check \"ec2-public-ip-check\" failed for resource \"aws.ec2/i-123\"." with input as fixture
}

test_non_compliant_description_includes_policy_message_when_present if {
	fixture := object.union_n([
		_payload("non_compliant"),
		{"raw_policy": {
			"name": "ec2-public-ip-check",
			"resource": "aws.ec2",
			"non_compliance_message": "Instance has a public IP address. Remove the public IP or document the approved exception.",
		}},
	])

	cloud_custodian_resources_detected.description == "Cloud Custodian check \"ec2-public-ip-check\" failed for resource \"aws.ec2/i-123\". Instance has a public IP address. Remove the public IP or document the approved exception." with input as fixture
}

test_non_compliant_description_includes_policy_message_before_execution_error if {
	fixture := object.union_n([
		_payload("non_compliant"),
		{
			"execution": {
				"status": "error",
				"dry_run": true,
				"exit_code": 1,
				"error": "custodian execution failed",
				"errors": ["custodian execution failed"],
			},
			"raw_policy": {
				"name": "ec2-public-ip-check",
				"resource": "aws.ec2",
				"non_compliance_message": "Instance has a public IP address. Remove the public IP or document the approved exception.",
			},
		},
	])

	cloud_custodian_resources_detected.description == "Cloud Custodian check \"ec2-public-ip-check\" failed for resource \"aws.ec2/i-123\". Instance has a public IP address. Remove the public IP or document the approved exception. Execution errors: custodian execution failed." with input as fixture
}

test_display_name_uses_last_arn_path_segment if {
	fixture := object.union_n([
		_payload("compliant"),
		{
			"check": {
				"name": "iam-role-missing-cost-code-tags",
				"resource": "aws.iam-role",
				"provider": "aws",
			},
			"resource": {
				"id": "arn:aws:iam::448923944987:role/aws-service-role/resource-explorer-2.amazonaws.com/AWSServiceRoleForResourceExplorer",
				"type": "aws.iam-role",
				"provider": "aws",
			},
		},
	])

	cloud_custodian_resources_detected.title == "Cloud Custodian check iam-role-missing-cost-code-tags on resource aws.iam-role/AWSServiceRoleForResourceExplorer" with input as fixture
	cloud_custodian_resources_detected.description == "Cloud Custodian check \"iam-role-missing-cost-code-tags\" passed for resource \"aws.iam-role/AWSServiceRoleForResourceExplorer\"." with input as fixture
	labels := cloud_custodian_resources_detected.labels with input as fixture
	labels.resource_id == "arn:aws:iam::448923944987:role/aws-service-role/resource-explorer-2.amazonaws.com/AWSServiceRoleForResourceExplorer"
	labels.resource_name == "AWSServiceRoleForResourceExplorer"
}

test_display_name_uses_last_colon_segment_when_no_path if {
	fixture := object.union_n([
		_payload("compliant"),
		{"resource": {
			"id": "arn:aws:s3:::example-bucket",
			"type": "aws.s3",
			"provider": "aws",
		}},
	])

	cloud_custodian_resources_detected.title == "Cloud Custodian check ec2-public-ip-check on resource aws.s3/example-bucket" with input as fixture
}

test_display_name_handles_leading_or_trailing_path_separators if {
	trailing := object.union_n([
		_payload("compliant"),
		{"resource": {
			"id": "role/aws-service-role/",
			"type": "aws.iam-role",
			"provider": "aws",
		}},
	])
	leading := object.union_n([
		_payload("compliant"),
		{"resource": {
			"id": "/AWSServiceRoleForResourceExplorer",
			"type": "aws.iam-role",
			"provider": "aws",
		}},
	])

	cloud_custodian_resources_detected.title == "Cloud Custodian check ec2-public-ip-check on resource aws.iam-role/aws-service-role" with input as trailing
	cloud_custodian_resources_detected.title == "Cloud Custodian check ec2-public-ip-check on resource aws.iam-role/AWSServiceRoleForResourceExplorer" with input as leading
}

test_labels_include_dedupe_and_optional_context_values if {
	fixture := _payload("non_compliant")

	labels := cloud_custodian_resources_detected.labels with input as fixture
	labels.resource_type == "aws.ec2"
	labels.resource_id == "i-123"
	labels.resource_name == "i-123"
	labels.provider == "aws"
	labels.account_id == "123456789012"
	labels.region == "us-east-1"
}

test_risk_templates_are_resource_deduped if {
	fixture := _payload("non_compliant")

	risk_templates := cloud_custodian_resources_detected.risk_templates with input as fixture
	count(risk_templates) == 3
	risk_templates[0].name == "Cloud Custodian resource policy non-compliance"
	risk_templates[0].title == "Cloud resource {{ .resource_type }}/{{ .resource_name }} may be non-compliant"
	risk_templates[0].violation_ids == ["cloud_custodian_resource_non_compliant"]
	risk_templates[0].dedupe_label_keys == ["resource_type", "resource_id"]
	count(risk_templates[0].label_schema) == 6
	risk_templates[0].label_schema[0].key == "resource_type"
	risk_templates[0].label_schema[1].key == "resource_id"
	risk_templates[0].label_schema[2].key == "resource_name"
	risk_templates[0].label_schema[3].key == "provider"
	risk_templates[0].label_schema[3].description == "Cloud provider from the Cloud Custodian resource or check provider field when available"
	risk_templates[0].label_schema[4].key == "account_id"
	risk_templates[0].label_schema[5].key == "region"
	risk_templates[0].remediation.title == "Remediate the failing Cloud Custodian policy condition"
	count(risk_templates[0].remediation.tasks) == 4

	risk_templates[1].name == "Cloud Custodian resource evaluation failure"
	risk_templates[1].title == "Cloud Custodian could not fully evaluate {{ .resource_type }}/{{ .resource_name }}"
	risk_templates[1].violation_ids == ["cloud_custodian_resource_evaluation_failed"]
	risk_templates[1].dedupe_label_keys == ["resource_type", "resource_id"]
	count(risk_templates[1].label_schema) == 6
	risk_templates[1].remediation.title == "Investigate and rerun the failing Cloud Custodian evaluation"
	count(risk_templates[1].remediation.tasks) == 3

	risk_templates[2].name == "Cloud Custodian policy received unsupported input"
	risk_templates[2].title == "Cloud Custodian policy received unsupported input {{ .source }}/{{ .schema_version }}"
	risk_templates[2].violation_ids == ["cloud_custodian_unsupported_input"]
	risk_templates[2].dedupe_label_keys == ["source", "schema_version"]
	count(risk_templates[2].label_schema) == 2
	risk_templates[2].remediation.title == "Correct the Cloud Custodian policy input wiring"
	count(risk_templates[2].remediation.tasks) == 3
}

test_missing_optional_fields_fall_back_safely if {
	fixture := {
		"schema_version": "v2",
		"source": "cloud-custodian",
		"assessment": {"status": "non_compliant"},
	}

	labels := cloud_custodian_resources_detected.labels with input as fixture
	labels.resource_type == "unknown-resource-type"
	labels.resource_id == "unknown-resource-id"
	labels.resource_name == "unknown-resource-id"
	object.get(labels, "provider", "") == ""
	object.get(labels, "account_id", "") == ""
	object.get(labels, "region", "") == ""

	cloud_custodian_resources_detected.title == "Cloud Custodian check unknown-check on resource unknown-resource-type/unknown-resource-id" with input as fixture
	cloud_custodian_resources_detected.description == "Cloud Custodian check \"unknown-check\" failed for resource \"unknown-resource-type/unknown-resource-id\"." with input as fixture

	cloud_custodian_resources_detected.violation[{
		"id": "cloud_custodian_resource_non_compliant",
		"remarks": "Resource \"unknown-resource-type/unknown-resource-id\" failed Cloud Custodian policy \"unknown-check\" (resource=\"unknown-resource-type\"); the resource was found by this policy run (matched=false, inventory_status=\"unknown-inventory-status\", matched_resource_count=unknown).",
	}] with input as fixture
}
