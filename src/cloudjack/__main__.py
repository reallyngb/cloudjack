"""Entry point for ``python -m cloudjack``.

Delegates to :mod:`cloudjack.cli` so that both ``python -m cloudjack`` and the
installed console script ``cloudjack`` share the same behaviour.
"""

from cloudjack.cli import app

if __name__ == "__main__":
    app()
