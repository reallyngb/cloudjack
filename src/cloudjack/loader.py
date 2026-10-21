"""Load and validate synthetic AWS IAM data."""

import json
from pathlib import Path
from pydantic import ValidationError
from cloudjack.models import Account


class CloudJackLoadError(Exception):
    """Raised when the input JSON is malformed or invalid."""
    pass


def load_account(filepath: str | Path) -> Account:
    """Read a JSON file and return a validated Account object.

    The file is opened with ``utf-8-sig``, which is UTF-8 that transparently
    strips a leading BOM if present. This makes CloudJack tolerant of files
    written by Windows PowerShell's ``Set-Content -Encoding utf8`` (which
    emits a BOM) as well as files written by editors or Git (which do not).
    """
    path = Path(filepath)
    if not path.exists():
        raise CloudJackLoadError(f"File not found: {path}")

    try:
        with open(path, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        raise CloudJackLoadError(f"Invalid JSON in {path.name}: {e}") from e

    try:
        return Account.model_validate(data)
    except ValidationError as e:
        raise CloudJackLoadError(f"Validation error in {path.name}:\n{e}") from e
