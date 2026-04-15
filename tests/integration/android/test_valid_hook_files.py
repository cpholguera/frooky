"""Tests for various valid hook files on Android."""
import pytest


@pytest.mark.parametrize("platform", ["android"], indirect=True)
class TestValidHookFiles:
    """Tests for handling errors on the target related to Java methods."""

    def test_single_method(self, run_frooky, count_matched_events):
        """Test hooking a single Java method in a real process."""

        hook_file = {
            "category": "STORAGE",
            "hooks": [
                {
                    "class": "androidx.security.crypto.EncryptedSharedPreferences$Editor",
                    "methods": [
                        "putString"
                    ]
                }
            ]
        }

        target_app = "mastg-demo-0060"

        run_frooky(hook_file, target_app)

        expected_pattern = {
            "class": "androidx.security.crypto.EncryptedSharedPreferences$Editor",
            "method": "putString",
        }

        assert count_matched_events(
            expected_pattern) == 2, "Not the amount of expected matched events found."

    def test_single_method_overload(self, run_frooky, count_matched_events):
        """Test hooking single Java methods and one overload."""

        hook_file = {
            "category": "STORAGE",
            "hooks": [
                {
                        "class": "androidx.security.crypto.EncryptedSharedPreferences",
                        "method": "create",
                        "overloads": [
                            {
                                "args": [
                                    "android.content.Context",
                                    "java.lang.String",
                                    "androidx.security.crypto.MasterKey",
                                    "androidx.security.crypto.EncryptedSharedPreferences$PrefKeyEncryptionScheme",
                                    "androidx.security.crypto.EncryptedSharedPreferences$PrefValueEncryptionScheme"
                                ]
                            }
                        ],
                    "filterEventsByStacktrace": ["org.owasp.mastestapp"]
                }
            ]
        }

        target_app = "mastg-demo-0060"

        run_frooky(hook_file, target_app)

        expected_event = {
            "class": "androidx.security.crypto.EncryptedSharedPreferences",
            "method": "create",
            "inputParameters": [
                {
                    "declaredType": "android.content.Context"
                },
                {
                    "declaredType": "java.lang.String"
                },
                {
                    "declaredType": "androidx.security.crypto.MasterKey"
                },
                {
                    "declaredType": "androidx.security.crypto.EncryptedSharedPreferences$PrefKeyEncryptionScheme"
                },
                {
                    "declaredType": "androidx.security.crypto.EncryptedSharedPreferences$PrefValueEncryptionScheme"
                }
            ],
        }

        assert count_matched_events(
            expected_event) == 1, "Not the amount of expected matched events found."

    def test_multiple_methods(self, run_frooky, count_matched_events):
        """Test hooking a single Java method in a real process."""

        hook_file = {
            "category": "STORAGE",
            "hooks": [
                {
                        "class": "androidx.security.crypto.EncryptedSharedPreferences$Editor",
                        "methods": [
                            "putString",
                            "putStringSet"
                        ],
                    "filterEventsByStacktrace": ["org.owasp.mastestapp"]
                }
            ]
        }

        target_app = "mastg-demo-0060"

        run_frooky(hook_file, target_app)

        expected_pattern_putString = {
            "class": "androidx.security.crypto.EncryptedSharedPreferences$Editor",
            "method": "putString",
        }

        expected_pattern_putStringSet = {
            "class": "androidx.security.crypto.EncryptedSharedPreferences$Editor",
            "method": "putStringSet",
        }

        assert count_matched_events(
            expected_pattern_putString) == 2, "Not the amount of expected matched events found."
        assert count_matched_events(
            expected_pattern_putStringSet) == 1, "Not the amount of expected matched events found."
