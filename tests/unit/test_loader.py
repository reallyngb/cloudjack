import json
import pytest
from cloudjack.loader import load_account, CloudJackLoadError


def test_load_valid_account(tmp_path):
    data = {
        "users": {
            "test-user": {
                "name": "test-user",
                "arn": "arn:aws:iam::123:user/test-user"
            }
        }
    }
    p = tmp_path / "valid.json"
    p.write_text(json.dumps(data))
    
    account = load_account(p)
    assert "test-user" in account.users
    assert account.users["test-user"].arn == "arn:aws:iam::123:user/test-user"


def test_load_missing_file():
    with pytest.raises(CloudJackLoadError, match="File not found"):
        load_account("does_not_exist.json")


def test_load_invalid_json(tmp_path):
    p = tmp_path / "invalid.json"
    p.write_text("{ this is not json }")
    with pytest.raises(CloudJackLoadError, match="Invalid JSON"):
        load_account(p)


def test_load_invalid_schema(tmp_path):
    data = {"users": {"test-user": {"missing_arn": True}}}
    p = tmp_path / "invalid_schema.json"
    p.write_text(json.dumps(data))
    with pytest.raises(CloudJackLoadError, match="Validation error"):
        load_account(p)
