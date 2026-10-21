"""Transparent risk scoring for attack paths."""

from cloudjack.models import AttackPath, RiskScore, Account

# The severity of different attack actions. Higher = worse.
ACTION_SEVERITY = {
    "access": 10,              # Direct access to a resource
    "sts:AssumeRole": 20,      # Assuming a role
    "iam:PassRole": 30,        # Passing a role to a service
    "iam:AttachUserPolicy": 50, # Attaching an admin policy
    "iam:AttachRolePolicy": 50,
    "iam:CreatePolicyVersion": 50,
}

def score_path(path: AttackPath, account: Account) -> RiskScore:
    """
    Calculate a 0-100 risk score.
    
    Weights:
    - Target Sensitivity (0-50 points): How critical is the destination?
    - Action Severity (10-50 points): How dangerous is the enabling action?
    - Path Length Penalty (0-20 points): Shorter paths are easier to execute.
    """
    # 1. Target Sensitivity (max 50)
    target_res = next((r for r in account.resources.values() if r.arn == path.target_resource), None)
    sensitivity = target_res.sensitivity if target_res else 1
    sensitivity_score = min(sensitivity * 10, 50)
    
    # 2. Action Severity (max 50)
    # We score based on the *worst* action in the path.
    max_action_severity = 0
    for step in path.steps:
        sev = ACTION_SEVERITY.get(step.action, 10)
        if sev > max_action_severity:
            max_action_severity = sev
            
    # 3. Path Length Penalty (max 20)
    # 1 step = 20 points. 2 steps = 15 points. 3+ steps = 10 points.
    if len(path.steps) == 1:
        length_score = 20
    elif len(path.steps) == 2:
        length_score = 15
    else:
        length_score = 10

    total = min(sensitivity_score + max_action_severity + length_score, 100)
    
    explanation = (
        f"Target sensitivity: {sensitivity_score}/50. "
        f"Action severity: {max_action_severity}/50. "
        f"Path length: {len(path.steps)} step(s) (+{length_score})."
    )

    return RiskScore(
        total=total,
        target_sensitivity=sensitivity_score,
        action_severity=max_action_severity,
        path_length_penalty=length_score,
        explanation=explanation
    )
