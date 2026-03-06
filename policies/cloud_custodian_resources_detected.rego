package compliance_framework.cloud_custodian_resources_detected

# Policy:
# 1) any matched resources in a Cloud Custodian check should produce a violation.
# 2) any execution error in a Cloud Custodian check should produce a violation.

check_name := object.get(object.get(input, "check", {}), "name", "unknown-check")

execution := object.get(input, "execution", {})
result := object.get(input, "result", {})

check_status := object.get(execution, "status", "unknown")

resources := object.get(result, "resources", [])
resource_count := count(resources)

has_resources if {
  is_array(resources)
  resource_count > 0
}

execution_error_message := object.get(execution, "error", "")
execution_error_list := object.get(execution, "errors", [])

has_execution_error if {
  execution_error_message != ""
}

has_execution_error if {
  is_array(execution_error_list)
  count(execution_error_list) > 0
}

violation[{"remarks": msg}] if {
  has_resources
  msg := sprintf("Cloud Custodian check %q matched %d resource(s).", [check_name, resource_count])
}

violation[{"remarks": msg}] if {
  has_execution_error
  msg := sprintf("Cloud Custodian check %q failed during execution (status=%q). error=%v errors=%v", [check_name, check_status, execution_error_message, execution_error_list])
}

title := sprintf("Cloud Custodian check %q status=%q", [check_name, check_status])

description := sprintf("Cloud Custodian check %q evaluated with status %q and matched %d resource(s). Execution errors (if any) are treated as violations.", [check_name, check_status, resource_count])
