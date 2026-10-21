"""Generate least-privilege remediations for attack paths."""

import copy
from cloudjack.models import Account, AttackPath, PolicyStatement

def generate_remediated_account(account: Account, path: AttackPath) -> Account:
    """
    Takes an account and an attack path, and returns a deep copy of the account
    with the specific permission that enabled the first step of the path removed.
    """
    remediated = account.model_copy(deep=True)
    first_step = path.steps[0]
    identity_arn = first_step.source
    
    # Find the identity in our cloned account
    target_identity = None
    if identity_arn in [u.arn for u in remediated.users.values()]:
        target_identity = next(u for u in remediated.users.values() if u.arn == identity_arn)
    elif identity_arn in [r.arn for r in remediated.roles.values()]:
        target_identity = next(r for r in remediated.roles.values() if r.arn == identity_arn)
        
    if not target_identity:
        return remediated

    # Look through all policies attached to the identity
    # We need to find the one that allows the first_step.action on first_step.target
    for policy in target_identity.get_all_policies():
        for statement in policy.get_statements():
            if statement.Effect != "Allow":
                continue
            
            # Very simplified check: if the action matches, we remove it entirely.
            # In a full version, we'd narrow down to specific resources.
            actions = statement.Action if isinstance(statement.Action, list) else [statement.Action]
            if first_step.action in actions or "*" in actions:
                # We found the permissive statement. Let's modify it.
                # If it's the only action, remove the statement. Otherwise, remove just the action.
                if isinstance(statement.Action, list) and len(statement.Action) > 1:
                    statement.Action.remove(first_step.action)
                else:
                    # Remove the entire statement by setting Effect to a dummy that we filter out
                    statement.Effect = "Deny" # Technically we can't set this to None due to typing
                    
    return remediated
