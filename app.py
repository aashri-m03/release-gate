from flask import Flask, request, jsonify
import re

app = Flask(__name__)


@app.route("/")
def home():
    return "Release Gate is running"


@app.route("/release-gate", methods=["POST"])
def release_gate():

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "decision": "block",
            "violations": []
        })

    workflow = data.get("workflow", {})
    image = data.get("image", {})

    violations = []

    # ---------------------------------
    # 1. Permissions
    # ---------------------------------

    expected_permissions = {
        "contents": "read",
        "packages": "write",
        "id-token": "none"
    }

    if workflow.get("permissions") != expected_permissions:
        violations.append("EXCESS_PERMISSION")

    # ---------------------------------
    # 2. Pull request trigger
    # ---------------------------------

    if data.get("event") == "pull_request":
        if workflow.get("trigger") != "pull_request":
            violations.append("UNSAFE_PR_TRIGGER")

    # ---------------------------------
    # 3. Tests
    # ---------------------------------

    if workflow.get("testsPassed") is not True:
        violations.append("TESTS_INCOMPLETE")

    elif workflow.get("matrixComplete") is not True:
        violations.append("TESTS_INCOMPLETE")

    elif workflow.get("failFast") is not False:
        violations.append("TESTS_INCOMPLETE")

    # ---------------------------------
    # 4. Actions
    # ---------------------------------

    for action in workflow.get("actions", []):

        owner = action.get("owner")
        ref = action.get("ref", "")

        if owner == "actions":
            continue

        if not re.fullmatch(r"[0-9a-f]{40}", ref):
            violations.append("MUTABLE_ACTION")
            break

    # ---------------------------------
    # 5. Docker image
    # ---------------------------------

    if image.get("multiStage") is not True:
        violations.append("SINGLE_STAGE_IMAGE")

    if image.get("runsAsRoot") is not False:
        violations.append("ROOT_RUNTIME")

    if image.get("secretMode") not in ["none", "buildkit"]:
        violations.append("SECRET_IN_LAYER")

    if image.get("criticalVulnerabilities") != 0:
        violations.append("CRITICAL_CVE")

    if image.get("digestPinned") is not True:
        violations.append("UNPINNED_IMAGE")

    # ---------------------------------
    # 6. Production
    # ---------------------------------

    if data.get("target") == "production":

        if (
            data.get("event") != "push"
            or data.get("ref") != "refs/heads/main"
        ):
            violations.append("INVALID_PRODUCTION_REF")

        if workflow.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    # Remove duplicates
    violations = list(dict.fromkeys(violations))

    if violations:
        return jsonify({
            "decision": "block",
            "violations": violations
        })

    return jsonify({
        "decision": "promote",
        "violations": []
    })


if __name__ == "__main__":
    import os

    port = int(os.environ.get("PORT", 5000))

    app.run(
        host="0.0.0.0",
        port=port
    )
