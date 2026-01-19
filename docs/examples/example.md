# Example: Hooking EncryptedSharedPreferences Methods

In this example we download and install the OWASP MAS [MASTG-DEMO-0060](https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0060/MASTG-DEMO-0060/) app (App Writing Sensitive Data to Sandbox using EncryptedSharedPreferences), create two hook files to hook methods related to encrypted shared preferences, and run `frooky` with both hook files against the app. We then analyze the output JSON Lines file to see the captured hook events.

## Creating Hook Files

First, create a hook file `hooks.json` to hook the `putString` and `putStringSet` methods of `android.app.SharedPreferencesImpl$EditorImpl`:

```json
{
  "category": "STORAGE",
  "hooks": [
    {
      "class": "android.app.SharedPreferencesImpl$EditorImpl",
      "methods": [
        "putString",
        "putStringSet"
      ]
    }
  ]
}
```

To demonstrate merging multiple hook files, we create a second hook file `hooks2.json` to hook the same methods in the underlying implementation class `androidx.security.crypto.EncryptedSharedPreferences$Editor`:

```json
{
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
```

## Running Frooky with Multiple Hook Files

```bash
frooky -U -n MASTestApp --platform android hooks.json hooks2.json

   ___    ____                                Powered by Frida 17.6.0
  / __\  / _  |    _     _    _  _   _   _    Target: MASTestApp
 / _\   | (_) |  / _ \ / _ \ | / /  | | | |   
/ /     / / | | | (_) | (_) ||  <   | |_| |   Device: Android Emulator 5554 (emulator-5554)
\/     /_/  |_|  \___/ \___/ |_|\_\  \__, |   Platform: android
                                     |___/    Hook files: 2
                                              Output: output.json

  Press Ctrl+C to stop...


  Resolved Hooks: 4
  Events: 6             | Last: androidx.security.crypto.EncryptedSharedPreferences$Editor.p...                

  Stopping ...
```

Notice how `frooky` indicates the Frida version, target app, device, platform, and output file.

It reports `Hook files: 2` and `Resolved Hooks: 4`, indicating that hooks from both files were merged and set up successfully.

The "Events" line shows the total number of captured hook events (6 in this case) and the last hooked method called.

## Analyzing the Output

The output file `output.json` will contain the captured hook events:

```json
{
    "type": "summary",
    "hooks": [
        {
            "class": "android.app.SharedPreferencesImpl$EditorImpl",
            "method": "putString",
            "overloads": [
                {
                    "args": [
                        "java.lang.String",
                        "java.lang.String"
                    ]
                }
            ]
        },
        {
            "class": "android.app.SharedPreferencesImpl$EditorImpl",
            "method": "putStringSet",
            "overloads": [
                {
                    "args": [
                        "java.lang.String",
                        "java.util.Set"
                    ]
                }
            ]
        },
        {
            "class": "androidx.security.crypto.EncryptedSharedPreferences$Editor",
            "method": "putString",
            "overloads": [
                {
                    "args": [
                        "java.lang.String",
                        "java.lang.String"
                    ]
                }
            ]
        },
        {
            "class": "androidx.security.crypto.EncryptedSharedPreferences$Editor",
            "method": "putStringSet",
            "overloads": [
                {
                    "args": [
                        "java.lang.String",
                        "java.util.Set"
                    ]
                }
            ]
        }
    ],
    "totalHooks": 4,
    "errors": [],
    "totalErrors": 0
}
{
    "id": "98862c65-de96-4872-95fc-c367b90c68a0",
    "type": "hook",
    "category": "STORAGE",
    "time": "2026-01-19T10:45:50.454Z",
    "class": "android.app.SharedPreferencesImpl$EditorImpl",
    "method": "putString",
    "instanceId": 31636504,
    "stackTrace": [
        "android.app.SharedPreferencesImpl$EditorImpl.putString(Native Method)",
        "androidx.security.crypto.EncryptedSharedPreferences$Editor.putEncryptedObject(EncryptedSharedPreferences.java:389)",
        "androidx.security.crypto.EncryptedSharedPreferences$Editor.putString(EncryptedSharedPreferences.java:262)",
        "androidx.security.crypto.EncryptedSharedPreferences$Editor.putString(Native Method)",
        "org.owasp.mastestapp.MastgTest.mastgTest(MastgTest.kt:33)",
        "org.owasp.mastestapp.MainActivityKt.MainScreen$lambda$12$lambda$11(MainActivity.kt:101)",
        "org.owasp.mastestapp.MainActivityKt.$r8$lambda$Pm6AsbKBmypP53K-UABM21E_Xxk(Unknown Source:0)",
        "org.owasp.mastestapp.MainActivityKt$$ExternalSyntheticLambda3.run(D8$$SyntheticClass:0)"
    ],
    "inputParameters": [
        {
            "declaredType": "java.lang.String",
            "value": "AQMRC7NJHrnwtE5suFMVSkzr7Zz0m55Yz/Gt4MQ8jXR9LQ+W"
        },
        {
            "declaredType": "java.lang.String",
            "value": "AX4R5MZvOLo+hzcBjDtSvkF+ryFEcXM66M/nzU33MpDv6fh//WWbG93gDW6f4JFXsRvq8WHJNI4zIoalUw=="
        }
    ],
    "returnValue": [
        {
            "declaredType": "android.content.SharedPreferences$Editor",
            "value": "<instance: android.content.SharedPreferences$Editor, $className: android.app.SharedPreferencesImpl$EditorImpl>",
            "runtimeType": "android.app.SharedPreferencesImpl$EditorImpl",
            "instanceId": "31636504",
            "instanceToString": "android.app.SharedPreferencesImpl$EditorImpl@1e2bc18"
        }
    ]
}
... <TRUNCATED FOR BREVITY> ...
```

We can see the `summary` event at the start, followed by individual `hook` events capturing calls to the hooked methods along with their parameters, return values, and stack traces.

The summary event indicates no errors and a total of 4 resolved hooks:

- `android.app.SharedPreferencesImpl$EditorImpl.putString`
- `android.app.SharedPreferencesImpl$EditorImpl.putStringSet`
- `androidx.security.crypto.EncryptedSharedPreferences$Editor.putString`
- `androidx.security.crypto.EncryptedSharedPreferences$Editor.putStringSet`

The first hook event shows a call to `android.app.SharedPreferencesImpl$EditorImpl.putString`, capturing the input parameters (the key and encrypted value) and the return value (the editor instance). The stack trace provides context on where the method was called from within the app, specifically from `MastgTest.mastgTest`.

The input parameters in this event are:

- Key: `"AQMRC7NJHrnwtE5suFMVSkzr7Zz0m55Yz/Gt4MQ8jXR9LQ+W"`
- Encrypted Value: `"AX4R5MZvOLo+hzcBjDtSvkF+ryFEcXM66M/nzU33MpDv6fh//WWbG93gDW6f4JFXsRvq8WHJNI4zIoalUw=="`

Which represents the data being stored in the encrypted shared preferences. The "key" being the identifier for the stored value, and the "encrypted value" being the actual data stored in an encrypted format.

The return value indicates that the method returned an instance of `android.content.SharedPreferences$Editor`, allowing for method chaining.
