"""Tests for good case lifecycle on Android."""
from helpers.android_test_helpers import AndroidTestHelper


class TestHookJavaMethod:
    """Tests for handling errors on the target related to Java methods."""

    def test_hook_java_single_method(self, pid, hooks_dir, maestro_flow_path):
        """Test hooking a single Java method in a real process."""
        AndroidTestHelper.run_hook_test(
            hooks_dir / "java_single_method.json",
            "android.app.SharedPreferencesImpl$EditorImpl",
            ["putString"],
            pid,
            maestro_flow_path
        )

    def test_hook_java_multiple_methods(self, pid, hooks_dir, maestro_flow_path):
        """Test hooking multiple Java methods in a real process."""
        AndroidTestHelper.run_hook_test(
            hooks_dir / "java_multiple_methods.json",
            "androidx.security.crypto.EncryptedSharedPreferences$Editor",
            ["putString", "putStringSet"],
            pid,
            maestro_flow_path
        )
