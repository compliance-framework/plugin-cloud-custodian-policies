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
		"remarks": "Cloud Custodian check \"ec2-public-ip-check\" marked resource \"aws.ec2/i-123\" as non-compliant (matched=true, inventory_status=\"baseline\").",
	}]
}

test_compliant_resource_produces_no_violation if {
	fixture := _payload("compliant")

	count(cloud_custodian_resources_detected.violation) == 0 with input as fixture
}

test_dynamic_title_and_description_use_resource_payload if {
	fixture := _payload("non_compliant")

	cloud_custodian_resources_detected.title == "Cloud Custodian check ec2-public-ip-check on resource aws.ec2/i-123" with input as fixture
	cloud_custodian_resources_detected.description == "Cloud Custodian check \"ec2-public-ip-check\" evaluated resource \"aws.ec2/i-123\" with assessment status \"non_compliant\" and execution status \"success\"." with input as fixture
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
	cloud_custodian_resources_detected.description == "Cloud Custodian check \"iam-role-missing-cost-code-tags\" evaluated resource \"aws.iam-role/AWSServiceRoleForResourceExplorer\" with assessment status \"compliant\" and execution status \"success\"." with input as fixture
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
	count(risk_templates) == 1
	risk_templates[0].name == "Cloud Custodian resource policy non-compliance"
	risk_templates[0].title == "Cloud resource {{ .resource_type }}/{{ .resource_name }} may be non-compliant"
	risk_templates[0].violation_ids == ["cloud_custodian_resource_non_compliant"]
	risk_templates[0].dedupe_label_keys == ["resource_type", "resource_id"]
	count(risk_templates[0].label_schema) == 6
	risk_templates[0].label_schema[0].key == "resource_type"
	risk_templates[0].label_schema[1].key == "resource_id"
	risk_templates[0].label_schema[2].key == "resource_name"
	risk_templates[0].label_schema[3].key == "provider"
	risk_templates[0].label_schema[4].key == "account_id"
	risk_templates[0].label_schema[5].key == "region"
	risk_templates[0].remediation.title == "Remediate the failing Cloud Custodian policy condition"
	count(risk_templates[0].remediation.tasks) == 4
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
	cloud_custodian_resources_detected.description == "Cloud Custodian check \"unknown-check\" evaluated resource \"unknown-resource-type/unknown-resource-id\" with assessment status \"non_compliant\" and execution status \"unknown-execution-status\"." with input as fixture

	cloud_custodian_resources_detected.violation[{
		"id": "cloud_custodian_resource_non_compliant",
		"remarks": "Cloud Custodian check \"unknown-check\" marked resource \"unknown-resource-type/unknown-resource-id\" as non-compliant (matched=false, inventory_status=\"unknown-inventory-status\").",
	}] with input as fixture
}
