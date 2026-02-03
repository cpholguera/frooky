"""Tests for good case lifecycle on Android."""
from helpers.android_test_helpers import AndroidTestHelper


class TestHookJavaMethod:
    """Tests for handling errors on the target related to Java methods."""

    def test_hook_single_java_method(self, pid, hooks_dir, maestro_flow_path):
        """Test hooking a single Java method in a real process."""
        AndroidTestHelper.run_hook_test(
            hooks_dir / "single_java_method.json",
            "android.app.SharedPreferencesImpl$EditorImpl",
            ["putString"],
            pid,
            maestro_flow_path
        )

    def test_hook_multiple_java_methods(self, pid, hooks_dir, maestro_flow_path):
        """Test hooking multiple Java methods in a real process."""
        AndroidTestHelper.run_hook_test(
            hooks_dir / "multiple_java_methods.json",
            "androidx.security.crypto.EncryptedSharedPreferences$Editor",
            ["putString", "putStringSet"],
            pid,
            maestro_flow_path
        )
