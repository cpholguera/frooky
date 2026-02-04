"""Tests for good case lifecycle on Android."""
from conftest import run_hook_test

class TestHookJavaMethod:
    """Tests for handling errors on the target related to Java methods."""

    def test_hook_java_single_method(self, pid, hooks_dir, maestro_flow_path):
        """Test hooking a single Java method in a real process."""

        target_patterns = [
            {
                "class": "android.app.SharedPreferencesImpl$EditorImpl",
                "method": "putString",
            }
        ]

        run_hook_test(
            hooks_dir / "java_single_method.json",
            target_patterns,
            pid,
            maestro_flow_path,
            "android"
        )

    def test_hook_java_multiple_methods(self, pid, hooks_dir, maestro_flow_path):
        """Test hooking multiple Java methods in a real process."""

        target_patterns = [
            {
                "class": "androidx.security.crypto.EncryptedSharedPreferences$Editor",
                "method": "putString",
            },
            {
                "class": "androidx.security.crypto.EncryptedSharedPreferences$Editor",
                "method": "putStringSet",
            },
        ]

        run_hook_test(
            hooks_dir / "java_multiple_methods.json",
            target_patterns,
            pid,
            maestro_flow_path,
            "android"
        )
