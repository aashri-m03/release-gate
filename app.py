from flask import Flask, request, jsonify
import re
import os

app = Flask(__name__)


@app.get("/")
def home():
    return "Release Gate is running"


@app.post("/release-gate")
def release_gate():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "decision": "block",
            "violations": ["TESTS_INCOMPLETE"]
        })

    workflow = data.get("workflow") or {}
    image = data.get("image") or {}

    violations = []

    # 1. EXACT permissions
    if workflow.get("permissions") != {
        "contents": "read",
        "packages": "write",
        "id-token": "none"
    }:
        violations.append("EXCESS_PERMISSION")

    # 2. PR must use pull_request
    if data.get("event") == "pull_request":
        if workflow.get("trigger") != "pull_request":
            violations.append("UNSAFE_PR_TRIGGER")

    # 3. All tests must satisfy all three conditions
    if (
        workflow.get("testsPassed") is not True
        or workflow.get("matrixComplete") is not True
        or workflow.get("failFast") is not False
    ):
        violations.append("TESTS_INCOMPLETE")

    # 4. Action pinning
    for action in workflow.get("actions", []):
        owner = action.get("owner")
        ref = action.get("ref", "")

        # actions/* is allowed to use tags
        if owner == "actions":
            continue

        # Every third-party action needs a lowercase 40-char SHA
        if not re.fullmatch(r"[0-9a-f]{40}", ref):
            violations.append("MUTABLE_ACTION")
            break

    # 5. Image checks
    if image.get("multiStage") is not True:
        violations.append("SINGLE_STAGE_IMAGE")

    if image.get("runsAsRoot") is not False:
        violations.append("ROOT_RUNTIME")

    if image.get("secretMode") not in ("none", "buildkit"):
        violations.append("SECRET_IN_LAYER")

    if image.get("criticalVulnerabilities") != 0:
        violations.append("CRITICAL_CVE")

    if image.get("digestPinned") is not True:
        violations.append("UNPINNED_IMAGE")

    # 6. Production checks
    if data.get("target") == "production":

        if (
            data.get("event") != "push"
            or data.get("ref") != "refs/heads/main"
        ):
            violations.append("INVALID_PRODUCTION_REF")

        if workflow.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    # No duplicate violation codes
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
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000))
    )
