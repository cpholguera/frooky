"""Tests for good case lifecycle on iOS."""
import pytest


@pytest.mark.parametrize("platform", ["ios"], indirect=True)
class TestHookNativeMethod:
    """Tests for handling errors on the target related to Java methods."""

    def test_hook_native(self, run_frooky, count_matched_events):
        """Test hooking a single iOS method in a real process."""

        hooks = {
            "category": "AUTH",
            "hooks": [
                {
                    "native": True,
                    "symbol": "- canEvaluatePolicy:error:",
                    "objClass": "LAContext"
                }
            ]
        }

        run_frooky(hooks)

        expected_event = {
            "type": "objc-hook",
            "symbol": "- canEvaluatePolicy:error:",
            "class": "LAContext"
        }

        assert count_matched_events(
            expected_event) == 1, "Not the amount of expected matched events found."
