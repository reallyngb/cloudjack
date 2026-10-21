"""Build a NetworkX graph of IAM identities and resources."""

import fnmatch
import networkx as nx
from cloudjack.models import Account
from cloudjack.policy import is_allowed


def _get_resource_service(arn: str) -> str | None:
    parts = arn.split(":")
    if len(parts) < 3:
        return None
    return parts[2]


def build_graph(account: Account) -> nx.DiGraph:
    """Construct a directed graph where edges represent allowed actions."""
    G = nx.DiGraph()

    # 1. Add all identities as nodes
    for user_name, user in account.users.items():
        G.add_node(user.arn, type="user", name=user_name)
    for role_name, role in account.roles.items():
        G.add_node(role.arn, type="role", name=role_name)

    # 2. Add all resources as nodes
    for res_name, res in account.resources.items():
        G.add_node(res.arn, type="resource", name=res_name, sensitivity=res.sensitivity)

    # 3. Connect identities to resources based on their policies
    all_identities = list(account.users.values()) + list(account.roles.values())

    for identity in all_identities:
        policies = identity.get_all_policies()

        for res_name, res in account.resources.items():
            service = _get_resource_service(res.arn)
            if not service:
                continue

            has_access = False
            evidence = ""

            # Manually scan policies to see if they grant ANY action for this service
            for policy in policies:
                for statement in policy.get_statements():
                    if statement.Effect != "Allow":
                        continue
                    
                    # Check if resource matches
                    res_patterns = statement.Resource if isinstance(statement.Resource, list) else [statement.Resource]
                    if not any(fnmatch.fnmatch(res.arn, p) for p in res_patterns):
                        continue
                        
                    # Check if any action matches the service
                    actions = statement.Action if isinstance(statement.Action, list) else [statement.Action]
                    for action in actions:
                        if action == "*" or action.startswith(f"{service}:"):
                            has_access = True
                            evidence = f"Policy allows {action} on {res.arn}"
                            break
                    if has_access:
                        break
                if has_access:
                    break

            if has_access:
                G.add_edge(
                    identity.arn,
                    res.arn,
                    action="access",
                    evidence=evidence,
                )

    # 4. Connect identities to roles they can assume
    for user in account.users.values():
        for role_name, role in account.roles.items():
            if is_allowed(user.get_all_policies(), "sts:AssumeRole", role.arn):
                trust_allowed = is_allowed([role.trust_policy], "sts:AssumeRole", user.arn)
                if trust_allowed:
                    G.add_edge(
                        user.arn,
                        role.arn,
                        action="sts:AssumeRole",
                        evidence="User policy allows AssumeRole and role trusts the user",
                    )

    return G
