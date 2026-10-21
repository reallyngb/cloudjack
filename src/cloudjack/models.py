"""Pydantic models for AWS IAM data ingestion and attack paths."""

from typing import Any, Literal
from pydantic import BaseModel, Field, field_validator


class PolicyStatement(BaseModel):
    Sid: str | None = None
    Effect: Literal["Allow", "Deny"]
    Action: str | list[str] | None = None
    NotAction: str | list[str] | None = None
    Resource: str | list[str] = "*"
    NotResource: str | list[str] | None = None
    Condition: dict[str, Any] | None = None
    Principal: str | dict[str, Any] | None = None

    @field_validator("Effect", mode="before")
    @classmethod
    def title_case_effect(cls, v: str) -> str:
        if isinstance(v, str):
            return v.capitalize()
        return v

    @field_validator("Action", "Resource", "NotAction", "NotResource", mode="before")
    @classmethod
    def ensure_str_or_list(cls, v: Any) -> Any:
        if isinstance(v, str):
            return [v]
        if isinstance(v, list):
            return v
        return v


class PolicyDocument(BaseModel):
    Version: str = "2012-10-17"
    Statement: list[PolicyStatement] | PolicyStatement

    def get_statements(self) -> list[PolicyStatement]:
        if isinstance(self.Statement, list):
            return self.Statement
        return [self.Statement]


class InlinePolicy(BaseModel):
    PolicyName: str
    PolicyDocument: PolicyDocument


class IamIdentity(BaseModel):
    name: str
    arn: str
    inline_policies: dict[str, PolicyDocument] = Field(default_factory=dict)
    managed_policies: list[PolicyDocument] = Field(default_factory=list)

    def get_all_policies(self) -> list[PolicyDocument]:
        return list(self.inline_policies.values()) + self.managed_policies


class IamUser(IamIdentity):
    pass


class IamRole(IamIdentity):
    trust_policy: PolicyDocument


class Resource(BaseModel):
    name: str
    arn: str
    type: str
    sensitivity: int = 1


class Account(BaseModel):
    users: dict[str, IamUser] = Field(default_factory=dict)
    roles: dict[str, IamRole] = Field(default_factory=dict)
    resources: dict[str, Resource] = Field(default_factory=dict)

    def get_identity(self, name: str) -> IamIdentity | None:
        return self.users.get(name) or self.roles.get(name)


# --- Attack Path Models ---

class AttackStep(BaseModel):
    """A single hop in an attack path."""
    source: str
    action: str
    target: str
    evidence: str


class AttackPath(BaseModel):
    """A complete path from a starting identity to a target."""
    start_identity: str
    target_resource: str
    steps: list[AttackStep]
    confidence: Literal["theoretical", "policy_supported", "validated"] = "policy_supported"
