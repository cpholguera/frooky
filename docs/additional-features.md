# Additional Settings and Best Practices

This documentation explains settings which are more general:

- [Event Filter Based on Stack Trace](#event-filter-based-on-stack-trace)
- [Stack Trace Limits](#stack-trace-limits)
- [Debugging](#debugging)

## Event Filter Based on Stack Trace

If you hook a method that is used widely, you may capture many events you are not interested in. This makes the analysis more difficult.

An example is `SharedPreferences` on Android. Let's assume you want to know whether the target app uses them to store sensitive data on the device:

```yaml
javaClass: android.app.SharedPreferencesImpl$EditorImpl
methods:
  - name: putString
```

frooky will capture the events you are looking for, as well as many more, such as the following one:

```json
{
  "id": "169a35b1-da19-492f-a90c-74d7cc5bdb3a",
  "type": "hook",
  "category": "STORAGE",
  "time": "2026-02-09T09:08:32.125Z",
  "class": "android.app.SharedPreferencesImpl$EditorImpl",
  "method": "putString",
  "instanceId": 175301911,
  "stackTrace": [
    "android.app.SharedPreferencesImpl$EditorImpl.putString(Native Method)",
    "com.google.crypto.tink.integration.android.SharedPrefKeysetWriter.write(SharedPrefKeysetWriter.java:70)",
    "com.google.crypto.tink.KeysetHandle.writeWithAssociatedData(KeysetHandle.java:869)",
    "com.google.crypto.tink.KeysetHandle.write(KeysetHandle.java:858)",
    "com.google.crypto.tink.integration.android.AndroidKeysetManager$Builder.generateKeysetAndWriteToPrefs(AndroidKeysetManager.java:353)",
    "com.google.crypto.tink.integration.android.AndroidKeysetManager$Builder.build(AndroidKeysetManager.java:292)",
    "androidx.security.crypto.EncryptedSharedPreferences.create(EncryptedSharedPreferences.java:169)",
    "androidx.security.crypto.EncryptedSharedPreferences.create(EncryptedSharedPreferences.java:131)"
  ],
  "inputParameters": [
    {
      "declaredType": "java.lang.String",
      "value": "__androidx_security_crypto_encrypted_prefs_key_keyset__"
    },
[...]
```

This method call is initiated by Android when `EncryptedSharedPreferences` are initiated. This library uses `SharedPreferences` to store an encryption key.

These events are usually not of interest to security testers, who want to test the target app rather than OS libraries.

To filter out events that do not originate from the target app, frooky can filter events based on the stack trace. The following `<hook_configuration>` will capture only events where the target package name matches the stack trace:

```yaml
javaClass: android.app.SharedPreferencesImpl$EditorImpl
methods:
  - name: putString
  - stackTraceFilter: ["^org\.owasp\.mastestapp"]
```

With this filter, noise can be reduced.

## Stack Trace Limits

By default, frooky will show all function calls of a stack trace. If this is too much, you can set a limit using the `stackTraceLimit` property. 

This is supported by Java, Objective-C and native hooks.


## Debugging

You can enable detailed debugging information using the property `debug`. 

The frooky agent will now send additional information in its event output.

