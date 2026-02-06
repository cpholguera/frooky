"""Tests for good case lifecycle on iOS."""
import pytest


@pytest.mark.parametrize("platform", ["ios"], indirect=True)
class TestHookNativeMethod:
    """Tests for handling errors on the target related to Java methods."""

    def test_hook_native(self, run_frooky, number_of_matched_events, output_file_path):
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

        run_frooky(hooks)

        expected_event = {
            "type": "native-hook",
            "symbol": "open",
            "inputParameters": [
                    {
                        "type": "string",
                        "name": "path"
                    }
            ],
        }

        assert output_file_path.exists(), "output.json was not created"
        assert number_of_matched_events(
            expected_event) == 4, "Not the amount of expected matched events found."
