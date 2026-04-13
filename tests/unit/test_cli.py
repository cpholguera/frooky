"""Tests for CLI functionality such as parsing arguments or command validation."""

import pytest
from frooky.cli import build_parser


class TestArgumentParsing:
    """Tests for CLI argument parsing functionality."""

    def test_parser_requires_platform(self, capsys):
        """Platform positional argument is required"""
        parser = build_parser()
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(["-U", "-F", "hooks.yaml"])

        assert exc_info.value.code == 2
        captured = capsys.readouterr()
        print(captured)
        assert "error: argument platform" in captured.err.lower()
        assert "(choose from android, ios)" in captured.err.lower()

    def test_parser_invalid_platform(self, capsys):
        """Platform argument is required"""
        invalid_platform = "windows_phone"
        parser = build_parser()
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(
                [invalid_platform, "-U", "-F", "hooks.yaml"])

        assert exc_info.value.code == 2
        captured = capsys.readouterr()
        assert "invalid choice" in captured.err.lower()
        assert invalid_platform in captured.err.lower()
