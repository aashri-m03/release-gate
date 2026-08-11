from flask import Flask, request, jsonify
import re

app = Flask(__name__)

EXPECTED_PERMISSIONS = {
    "contents": "read",
    "packages": "write",
    "id-token": "none"
}

SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")


@app.post("/release-gate")
def release_gate():
    data = request.get_json(silent=True) or {}

    violations = []

    target = data.get("target")
    event = data.get("event")
    ref = data.get("ref")

    workflow = data.get("workflow") or {}
    image = data.get("image") or {}

    # Rule 1: permissions must match exactly.
    permissions = workflow.get("permissions") or {}

    if permissions != EXPECTED_PERMISSIONS:
        violations.append("EXCESS_PERMISSION")

    # Rule 2: pull requests must use pull_request.
    if event == "pull_request":
        if workflow.get("trigger") != "pull_request":
            violations.append("UNSAFE_PR_TRIGGER")

    # Rule 3: tests and matrix must be complete.
    if (
        workflow.get("testsPassed") is not True
        or workflow.get("matrixComplete") is not True
        or workflow.get("failFast") is not False
    ):
        violations.append("TESTS_INCOMPLETE")

    # Rule 4: check Action references.
    actions = workflow.get("actions") or []

    for action in actions:
        owner = action.get("owner")
        action_ref = action.get("ref")

        # Actions owned by "actions" may use a version tag.
        if owner == "actions":
            continue

        # Every third-party Action needs a lowercase 40-character SHA.
        if not isinstance(action_ref, str) or not SHA_PATTERN.fullmatch(action_ref):
            violations.append("MUTABLE_ACTION")
            break

    # Rule 5: image must use multiple build stages.
    if image.get("multiStage") is not True:
        violations.append("SINGLE_STAGE_IMAGE")

    # Rule 6: image must run as a non-root user.
    if image.get("runsAsRoot") is not False:
        violations.append("ROOT_RUNTIME")

    # Rule 7: only no secret or BuildKit secret is allowed.
    if image.get("secretMode") not in {"none", "buildkit"}:
        violations.append("SECRET_IN_LAYER")

    # Rule 8: no critical vulnerabilities.
    if image.get("criticalVulnerabilities") != 0:
        violations.append("CRITICAL_CVE")

    # Rule 9: image must be digest-pinned.
    if image.get("digestPinned") is not True:
        violations.append("UNPINNED_IMAGE")

    # Rule 10: production must deploy from main using push.
    if target == "production":
        if event != "push" or ref != "refs/heads/main":
            violations.append("INVALID_PRODUCTION_REF")

        # Production also needs explicit approval.
        if workflow.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    # Remove duplicates while preserving the original order.
    violations = list(dict.fromkeys(violations))

    decision = "promote" if len(violations) == 0 else "block"

    return jsonify({
        "decision": decision,
        "violations": violations
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
