"""Tests for good case lifecycle on Android."""
import pytest


@pytest.mark.parametrize("platform", ["android"], indirect=True)
class TestHookJavaMethod:
    """Tests for handling errors on the target related to Java methods."""

    def test_hook_java_single_method(self, run_frooky, number_of_matched_events, output_file_path):
        """Test hooking a single Java method in a real process."""

        hook = {
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

        run_frooky(hook)

        expected_pattern = {
            "class": "androidx.security.crypto.EncryptedSharedPreferences$Editor",
            "method": "putString",
        }

        assert output_file_path.exists(), "output.json was not created"
        assert number_of_matched_events(
            expected_pattern) == 2, "Not the amount of expected matched events found."

    def test_hook_java_single_method_overload(self, run_frooky, number_of_matched_events, output_file_path):
        """Test hooking single Java methods and one overload."""

        hook = {
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

        run_frooky(hook)

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

        assert output_file_path.exists(), "output.json was not created"
        assert number_of_matched_events(
            expected_event) == 1, "Not the amount of expected matched events found."

    def test_hook_java_multiple_methods(self, run_frooky, number_of_matched_events, output_file_path):
        """Test hooking a single Java method in a real process."""

        hook = {
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

        run_frooky(hook)

        expected_pattern_putString = {
            "class": "androidx.security.crypto.EncryptedSharedPreferences$Editor",
            "method": "putString",
        }

        expected_pattern_putStringSet = {
            "class": "androidx.security.crypto.EncryptedSharedPreferences$Editor",
            "method": "putStringSet",
        }

        assert output_file_path.exists(), "output.json was not created"
        assert number_of_matched_events(
            expected_pattern_putString) == 2, "Not the amount of expected matched events found."
        assert number_of_matched_events(
            expected_pattern_putStringSet) == 1, "Not the amount of expected matched events found."
