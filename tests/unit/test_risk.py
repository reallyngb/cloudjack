from cloudjack.models import AttackPath, AttackStep, Account, Resource
from cloudjack.risk import score_path


def test_risk_scoring():
    account = Account(
        resources={
            "critical": Resource(name="critical", arn="arn:aws:s3:::critical", type="S3", sensitivity=10)
        }
    )
    path = AttackPath(
        start_identity="arn:aws:iam::123:user/intern",
        target_resource="arn:aws:s3:::critical",
        steps=[AttackStep(source="arn:aws:iam::123:user/intern", action="access", target="arn:aws:s3:::critical", evidence="test")]
    )
    
    score = score_path(path, account)
    assert score.target_sensitivity == 50
    assert score.action_severity == 10
    assert score.path_length_penalty == 20
    assert score.total == 80
