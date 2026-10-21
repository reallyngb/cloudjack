"""Build a NetworkX graph of IAM identities and resources."""

import networkx as nx
from cloudjack.models import Account
from cloudjack.policy import is_allowed


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
            # Check if the identity can access the resource directly
            if is_allowed(policies, "s3:GetObject", res.arn) or is_allowed(policies, "*", res.arn):
                G.add_edge(
                    identity.arn, 
                    res.arn, 
                    action="access", 
                    evidence=f"Policy allows access to {res.arn}"
                )

    # 4. Connect identities to roles they can assume (via trust policy and sts:AssumeRole)
    for user in account.users.values():
        for role_name, role in account.roles.items():
            # Check if user has sts:AssumeRole
            if is_allowed(user.get_all_policies(), "sts:AssumeRole", role.arn):
                # Check trust policy
                trust_allowed = is_allowed([role.trust_policy], "sts:AssumeRole", user.arn)
                if trust_allowed:
                    G.add_edge(
                        user.arn,
                        role.arn,
                        action="sts:AssumeRole",
                        evidence=f"User policy allows AssumeRole and role trusts the user"
                    )

    return G
