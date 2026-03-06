package compliance_framework.cloud_custodian_resources_detected_test

import data.compliance_framework.cloud_custodian_resources_detected

test_violation_when_resources_detected if {
  fixture := {
    "check": {"name": "ec2-public-ip-check"},
    "execution": {"status": "success", "error": "", "errors": []},
    "result": {
      "resources": [{"InstanceId": "i-123"}]
    }
  }

  cloud_custodian_resources_detected.violation[{
    "remarks": "Cloud Custodian check \"ec2-public-ip-check\" matched 1 resource(s)."
  }] with input as fixture
}

test_violation_when_execution_error_detected if {
  fixture := {
    "check": {"name": "ec2-public-ip-check"},
    "execution": {
      "status": "error",
      "error": "custodian execution failed",
      "errors": ["custodian execution failed"]
    },
    "result": {
      "resources": []
    }
  }

  cloud_custodian_resources_detected.violation[{
    "remarks": "Cloud Custodian check \"ec2-public-ip-check\" failed during execution (status=\"error\"). error=custodian execution failed errors=[\"custodian execution failed\"]"
  }] with input as fixture
}

test_dynamic_title_and_description if {
  fixture := {
    "check": {"name": "ec2-public-ip-check"},
    "execution": {"status": "error", "error": "boom", "errors": ["boom"]},
    "result": {
      "resources": [{"InstanceId": "i-123"}, {"InstanceId": "i-456"}]
    }
  }

  cloud_custodian_resources_detected.title == "Cloud Custodian check \"ec2-public-ip-check\" status=\"error\"" with input as fixture
  cloud_custodian_resources_detected.description == "Cloud Custodian check \"ec2-public-ip-check\" evaluated with status \"error\" and matched 2 resource(s). Execution errors (if any) are treated as violations." with input as fixture
}

test_no_violation_when_no_resources if {
  fixture := {
    "check": {"name": "ec2-public-ip-check"},
    "execution": {"status": "success", "error": "", "errors": []},
    "result": {
      "resources": []
    }
  }

  count(cloud_custodian_resources_detected.violation) == 0 with input as fixture
}
