import pytest
from cloudjack.models import PolicyDocument
from cloudjack.policy import is_allowed


def make_policy(statements):
    return PolicyDocument(Statement=statements)


def test_allow_exact():
    doc = make_policy([{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::bucket/file"}])
    assert is_allowed([doc], "s3:GetObject", "arn:aws:s3:::bucket/file") is True
    assert is_allowed([doc], "s3:PutObject", "arn:aws:s3:::bucket/file") is False


def test_wildcard_action():
    doc = make_policy([{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}])
    assert is_allowed([doc], "s3:GetObject", "arn:aws:s3:::bucket/file") is True
    assert is_allowed([doc], "ec2:DescribeInstances", "arn:aws:s3:::bucket/file") is False


def test_wildcard_resource():
    doc = make_policy([{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}])
    assert is_allowed([doc], "s3:GetObject", "arn:aws:s3:::any/bucket") is True


def test_explicit_deny():
    doc = make_policy([
        {"Effect": "Allow", "Action": "*", "Resource": "*"},
        {"Effect": "Deny", "Action": "s3:*", "Resource": "*"}
    ])
    assert is_allowed([doc], "ec2:DescribeInstances", "*") is True
    assert is_allowed([doc], "s3:GetObject", "*") is False


def test_default_deny():
    doc = make_policy([{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}])
    assert is_allowed([doc], "ec2:RunInstances", "*") is False
