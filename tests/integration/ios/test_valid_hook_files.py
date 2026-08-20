"""Tests for good case lifecycle on iOS."""
import pytest


@pytest.mark.parametrize("platform", ["ios"], indirect=True)
class TestValidHookFiles:
    """Tests for handling errors on the target related to Java methods."""

    def test_method(self, run_frooky, count_matched_events):
        """Test hooking a single iOS method in a real process."""

        hook_file = {
            "category": "AUTH",
            "hooks": [
                {
                    "native": True,
                    "symbol": "- canEvaluatePolicy:error:",
                    "objClass": "LAContext"
                }
            ]
        }

        target_app = "mastg-demo-0026"

        run_frooky(hook_file, target_app)

        expected_event = {
            "type": "objc-hook",
            "symbol": "- canEvaluatePolicy:error:",
            "class": "LAContext"
        }

        assert count_matched_events(
            expected_event) == 1, "Not the amount of expected matched events found."
