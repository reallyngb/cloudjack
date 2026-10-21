from cloudjack.models import PolicyDocument
from cloudjack.policy import is_allowed


def make_policy(statements):
    return PolicyDocument(Statement=statements)


def test_explicit_deny_overrides_allow_in_same_policy():
    doc = make_policy([
        {"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
        {"Effect": "Deny", "Action": "s3:GetObject", "Resource": "*"}
    ])
    assert is_allowed([doc], "s3:GetObject", "arn:aws:s3:::any") is False
    assert is_allowed([doc], "s3:PutObject", "arn:aws:s3:::any") is True


def test_explicit_deny_overrides_allow_in_different_policies():
    allow_doc = make_policy([{"Effect": "Allow", "Action": "*", "Resource": "*"}])
    deny_doc = make_policy([{"Effect": "Deny", "Action": "iam:*", "Resource": "*"}])
    
    assert is_allowed([allow_doc, deny_doc], "iam:CreateUser", "*") is False
    assert is_allowed([allow_doc, deny_doc], "s3:GetObject", "*") is True


def test_empty_policy_documents():
    assert is_allowed([], "s3:GetObject", "*") is False


def test_unsupported_condition_is_ignored():
    # We do not evaluate conditions yet, so they should default to "match"
    doc = make_policy([{
        "Effect": "Allow", 
        "Action": "s3:GetObject", 
        "Resource": "*",
        "Condition": {"StringEquals": {"aws:PrincipalTag/role": "admin"}}
    }])
    # Even though the condition might be false, we don't evaluate it, so we return True
    assert is_allowed([doc], "s3:GetObject", "arn:aws:s3:::any") is True
