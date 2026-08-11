from flask import Flask, request, jsonify
import re

app = Flask(__name__)


def check_release_gate(data):
    violations = []

    workflow = data.get("workflow", {})
    image = data.get("image", {})

    # 1. Permissions must be exactly least privilege
    expected_permissions = {
        "contents": "read",
        "packages": "write",
        "id-token": "none"
    }

    if workflow.get("permissions") != expected_permissions:
        violations.append("EXCESS_PERMISSION")

    # 2. Pull request must use pull_request
    if data.get("event") == "pull_request":
        if workflow.get("trigger") != "pull_request":
            violations.append("UNSAFE_PR_TRIGGER")

    # 3. Tests must pass, matrix complete, failFast false
    if (
        workflow.get("testsPassed") is not True
        or workflow.get("matrixComplete") is not True
        or workflow.get("failFast") is not False
    ):
        violations.append("TESTS_INCOMPLETE")

    # 4. Check GitHub Actions pinning
    for action in workflow.get("actions", []):
        owner = action.get("owner", "")
        ref = action.get("ref", "")

        if owner == "actions":
            # Official actions may use tags such as v4
            continue

        # Third-party actions must use exactly 40 lowercase hex chars
        if not re.fullmatch(r"[0-9a-f]{40}", ref):
            violations.append("MUTABLE_ACTION")
            break

    # 5. Docker image must be multi-stage
    if image.get("multiStage") is not True:
        violations.append("SINGLE_STAGE_IMAGE")

    # 6. Docker image must run as non-root
    if image.get("runsAsRoot") is not False:
        violations.append("ROOT_RUNTIME")

    # 7. Secrets must not be copied into image layers
    if image.get("secretMode") not in ("none", "buildkit"):
        violations.append("SECRET_IN_LAYER")

    # 8. No critical vulnerabilities
    if image.get("criticalVulnerabilities") != 0:
        violations.append("CRITICAL_CVE")

    # 9. Image must be digest pinned
    if image.get("digestPinned") is not True:
        violations.append("UNPINNED_IMAGE")

    # 10. Production must be push to main
    if data.get("target") == "production":
        if (
            data.get("event") != "push"
            or data.get("ref") != "refs/heads/main"
        ):
            violations.append("INVALID_PRODUCTION_REF")

        # 11. Production approval
        if workflow.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    decision = "promote" if not violations else "block"

    return {
        "decision": decision,
        "violations": violations
    }


@app.route("/release-gate", methods=["POST"])
def release_gate():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "decision": "block",
            "violations": ["TESTS_INCOMPLETE"]
        }), 400

    return jsonify(check_release_gate(data))


@app.route("/")
def home():
    return "Release Gate API is running"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
