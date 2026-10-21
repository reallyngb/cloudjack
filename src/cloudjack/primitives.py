"""Catalogue of known AWS IAM privilege escalation primitives."""

from typing import NamedTuple


class Primitive(NamedTuple):
    action: str
    description: str


# A subset of known escalation paths. For MVP, we focus on direct resource access,
# AssumeRole, and self-escalation via IAM modification.
ESCALATION_PRIMITIVES = [
    Primitive("sts:AssumeRole", "Assume a role to gain its permissions"),
    Primitive("iam:AttachUserPolicy", "Attach an admin policy to a user"),
    Primitive("iam:AttachRolePolicy", "Attach an admin policy to a role"),
    Primitive("iam:CreatePolicyVersion", "Create a new admin policy version"),
    Primitive("iam:PassRole", "Pass a role to an AWS service to execute actions"),
]
