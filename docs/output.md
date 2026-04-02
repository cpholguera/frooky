# Output Format

Events are written to the output file in JSON Lines format (one JSON object per line, known as NDJSON). You can pretty-print it easily, for example, using `jq . output.json`.

First, a summary event is written when hooking is initialized, listing all resolved hooks. It includes:

- `type`: Indicates this is a summary event
- `hooks`: An array of all hooked methods, including their classes and overloads
- `totalHooks`: The total number of hooks set up
- `errors`: Any errors encountered while setting up hooks
- `totalErrors`: The total number of errors encountered

After that, an individual hook event is written each time a hooked method or function is called.

Example hook event (pretty-printed for clarity):

```json
{
    "id": "0117229c-b034-4676-ba33-075fc27922ba",
    "type": "hook",
    "category": "STORAGE",
    "time": "2026-01-18T16:17:25.470Z",
    "class": "android.app.SharedPreferencesImpl$EditorImpl",
    "method": "putString",
    "instanceId": 268282727,
    "stackTrace": [
        "android.app.SharedPreferencesImpl$EditorImpl.putString(Native Method)",
        "androidx.security.crypto.EncryptedSharedPreferences$Editor.putEncryptedObject(EncryptedSharedPreferences.java:389)",
        ...
    ],
    "inputParameters": [
        {
            "declaredType": "java.lang.String",
            "value": "AQMRC7OWD6/h1iJseuzJVrClpwKE8swB8gOrGnsdaN4="
        },
        {
            "declaredType": "java.lang.String",
            "value": "AX4R5MZu+J1p0U3hvKyuEnJDQopI+wupiSi8CAG8dzq0PU76NbbebjhqMtqCD7fFUy2SmmQuQVDlDrrj30d3GQes+PlD8HmRFszVTge039GQ"
        }
    ],
    "returnValue": [
        {
            "declaredType": "android.content.SharedPreferences$Editor",
            "value": "<instance: android.content.SharedPreferences$Editor, $className: android.app.SharedPreferencesImpl$EditorImpl>",
            "runtimeType": "android.app.SharedPreferencesImpl$EditorImpl",
            "instanceId": "268282727",
            "instanceToString": "android.app.SharedPreferencesImpl$EditorImpl@ffdab67"
        }
    ]
}
```

Explanation of fields:

- `id`: Unique identifier for the event (UUID)
- `type`: Event type (e.g., "hook", "summary")
- `category`: Category specified in the hook file (e.g., "STORAGE", "CRYPTO")
- `time`: Event timestamp in ISO 8601 format
- `class`: Hooked class name
- `method`: Hooked method name
- `instanceId`: Unique identifier for the instance on which the method was called
- `stackTrace`: Captured stack trace leading to the method call
- `inputParameters`: Array of input parameters, each with its declared type and value
  - `declaredType`: The declared type of the parameter
  - `value`: The captured value of the parameter
- `returnValue`: Array of return values, each with its declared type, captured value, runtime type, instance ID, and string representation
  - `declaredType`: The declared type of the return value
  - `value`: The captured value of the return value
  - `runtimeType`: The actual runtime type of the return value
  - `instanceId`: Unique identifier for the return value instance
  - `instanceToString`: String representation of the return value instance
