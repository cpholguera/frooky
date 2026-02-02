import pytest
from frooky.cli import build_parser


class TestArgumentParsing:

    def test_parser_requires_platform(self, capsys):
        """Platform argument is required"""
        parser = build_parser()
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(["-U", "-F", "hooks.yaml"])

        assert exc_info.value.code == 2
        captured = capsys.readouterr()
        assert "the following arguments are required" in captured.err.lower()
        assert "--platform" in captured.err.lower()

    def test_parser_invalid_platform(self, capsys):
        """Platform argument is required"""
        invalid_platform = "windows_phone"
        parser = build_parser()
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(["-U", "-F", "--platform", invalid_platform, "hooks.yaml"])

        assert exc_info.value.code == 2
        captured = capsys.readouterr()
        assert "invalid choice" in captured.err.lower()
        assert invalid_platform in captured.err.lower()

