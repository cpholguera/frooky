# Building Target Apps

Tests usually require a target app which implements the feature that should be tested. For example, type decoders should be tested against real implementations on Android or iOS.

These apps are located in the folder `tests/target-apps/<android|ios>/`. They must be in the form of a [MASTG-DEMO app](https://mas.owasp.org/MASTG/demos/#) Hence, the app identifier for the Android app is `org.owasp.mastestapp` and for the iOS app `org.owasp.mastestapp.MASTestApp-iOS`.

To compile them, run `make build APP_DIR=<app-dir>` in the directory `tests/target-apps/<android|ios>/`.

`app-dir` is the folder where the demo app is. If no `APP_DIR` is provided, an empty [`mas-app-ios`](https://github.com/cpholguera/mas-app-ios) or [`mas-app-android`](https://github.com/cpholguera/mas-app-android) app is built.

**Examples 1:** Building an empty `mas-app-ios` app:

```sh
cd tests/target-apps/ios
make build
```

This will compile the app and store it in `tests/target-apps/ios/dist/MASTestApp.app`.

**Examples 2:** Building a custom for parameter testing

```sh
cd tests/target-apps/android
make build APP_DIR=./basic-parameter
```

This will compile the app and store it in `tests/target-apps/android/dist/MASTestApp.apk`.

> [!NOTE]
> At the moment, there is no automation to start the app.
> This means, the developer is responsible that the right target app is running on the device and that Frida is available.
> Agent tests will always just start the target app based on the app identifier.
