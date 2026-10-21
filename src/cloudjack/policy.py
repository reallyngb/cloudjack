"""Core IAM policy evaluation logic."""

import fnmatch
from cloudjack.models import PolicyDocument, PolicyStatement


def _matches(pattern: list[str], value: str) -> bool:
    """Check if a value matches any pattern in the list, supporting wildcards."""
    for p in pattern:
        if fnmatch.fnmatch(value, p):
            return True
    return False


def evaluate_statement(statement: PolicyStatement, action: str, resource: str) -> bool:
    """Return True if the statement matches the action and resource."""
    # 1. Check Actions
    if statement.Action:
        if not _matches(statement.Action, action):
            return False
    elif statement.NotAction:
        if _matches(statement.NotAction, action):
            return False

    # 2. Check Resources
    if statement.Resource:
        if not _matches(statement.Resource, resource):
            return False
    elif statement.NotResource:
        if _matches(statement.NotResource, resource):
            return False

    # 3. Conditions (MVP: we explicitly skip evaluating them, but document it)
    if statement.Condition:
        # For now, if there is a condition we don't understand, we assume it doesn't block us.
        pass

    return True


def is_allowed(policies: list[PolicyDocument], action: str, resource: str) -> bool:
    """
    Evaluate a list of policies against an action and resource.
    Implements AWS policy evaluation logic: Explicit Deny > Allow > Default Deny.
    """
    allowed = False
    
    for policy in policies:
        for statement in policy.get_statements():
            if evaluate_statement(statement, action, resource):
                if statement.Effect == "Deny":
                    return False  # Explicit Deny beats everything
                elif statement.Effect == "Allow":
                    allowed = True

    return allowed
