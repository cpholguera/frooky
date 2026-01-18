from __future__ import annotations

from importlib import resources


def read_text(path: str) -> str:
    return resources.files("frooky").joinpath(path).read_text(encoding="utf-8")
