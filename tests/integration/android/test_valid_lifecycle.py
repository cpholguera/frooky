"""Tests for good case lifecycle on Android."""
from conftest import run_frooky, contains_subset_of


class TestHookJavaMethod:
    """Tests for handling errors on the target related to Java methods."""

    def test_hook_java_single_method(self, pid, output_file_path, android_mastestapp_start):
        """Test hooking a single Java method in a real process."""

        hooks = {
            "category": "STORAGE",
            "hooks": [
                {
                        "class": "android.app.SharedPreferencesImpl$EditorImpl",
                        "methods": [
                            "putString"
                        ]
                }
            ]
        }

        run_frooky("android", hooks, pid, output_file_path,
                   android_mastestapp_start)

        expected_patterns = [
            {
                "class": "android.app.SharedPreferencesImpl$EditorImpl",
                "method": "putString",
            }
        ]

        assert output_file_path.exists(), "output.json was not created"
        assert contains_subset_of(
            expected_patterns, output_file_path), "output.json did not contain the expected pattern as a subset."

    def test_hook_java_multiple_methods(self, pid, output_file_path, android_mastestapp_start):
        """Test hooking multiple Java methods in a real process."""

        hooks = {
            "category": "STORAGE",
            "hooks": [
                {
                        "class": "androidx.security.crypto.EncryptedSharedPreferences$Editor",
                        "methods": [
                            "putString",
                            "putStringSet"
                        ]
                }
            ]
        }

        run_frooky("android", hooks, pid, output_file_path,
                   android_mastestapp_start)

        expected_patterns = [
            {
                "class": "androidx.security.crypto.EncryptedSharedPreferences$Editor",
                "method": "putString",
            },
            {
                "class": "androidx.security.crypto.EncryptedSharedPreferences$Editor",
                "method": "putStringSet",
            },
        ]

        assert output_file_path.exists(), "output.json was not created"
        assert contains_subset_of(
            expected_patterns, output_file_path), "output.json did not contain the expected pattern as a subset."

    def test_hook_java_single_method_overload(self, pid, output_file_path, android_mastestapp_start):
        """Test hooking single Java methods and one overload."""

        hooks = {
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
                        ]
                }
            ]
        }

        run_frooky("android", hooks, pid, output_file_path,
                   android_mastestapp_start)

        expected_patterns = [
            {
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
        ]

        assert output_file_path.exists(), "output.json was not created"
        assert contains_subset_of(
            expected_patterns, output_file_path), "output.json did not contain the expected pattern as a subset."
