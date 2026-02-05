"""Tests for good case lifecycle on iOS."""
import pytest
from conftest import run_frooky, contains_subset_of


@pytest.mark.parametrize("platform", ["ios"], indirect=True)
class TestHookNativeMethod:
    """Tests for handling errors on the target related to Java methods."""

    def test_hook_native(self, platform, pid, output_file_path, mastestapp_start):
        """Test hooking a single Java method in a real process."""

        hooks = {
            "category": "STORAGE",
            "hooks": [
                {
                    "native": True,
                    "symbol": "open",
                    "maxFrames": 5,
                    "filterEventsByStacktrace": "MASTestApp",
                    "args": [
                        {
                            "type": "string",
                            "name": "path",
                            "filter": ["Containers/Data/Application/"]
                        }
                    ]
                }
            ]
        }

        run_frooky(platform, hooks, pid, output_file_path, mastestapp_start)

        expected_patterns = [
            {
                "type": "native-hook",
                "symbol": "open",
                "inputParameters": [
                    {
                        "type": "string",
                        "name": "path"
                    }
                ],
            }
        ]

        assert output_file_path.exists(), "output.json was not created"
        assert contains_subset_of(
            expected_patterns, output_file_path), "output.json did not contain the expected pattern as a subset."
