# Target Apps

Tests usually require a target app which implements the feature that should be tested. For example, type decoders should be tested against real implementations on Android or iOS.

For that frooky used target apps.

## Building Target Apps

These apps are located in the folder `tests/target-apps/<android|ios>/`. They must be in the form of a [MASTG-DEMO app](https://mas.owasp.org/MASTG/demos/). Hence, the app identifier for the Android app is `org.owasp.mastestapp` and for the iOS app `org.owasp.mastestapp.MASTestApp-iOS`.

Make sure, that you have all the prerequisites met to compile Android or iOS apps. For Android, you need to install [Android Studio](https://developer.android.com/studio), for iOS [Xcode](https://developer.apple.com/xcode/).

To compile them, go to either `tests/target-apps/<android|ios>/` and run:

- `make build APP_DIR=<app-dir>` to build a custom app.
- `make build` to build an empty [`mas-app-ios`](https://github.com/cpholguera/mas-app-ios) or [`mas-app-android`](https://github.com/cpholguera/mas-app-android) app.

**Example 1:** Build an empty `mas-app-ios` app:

```sh
cd tests/target-apps/ios
make build
```

This will compile the app and store it in `tests/target-apps/ios/dist/MASTestApp.app`.

**Example 2:** Build a custom `mas-app-android` app:

```sh
cd tests/target-apps/android
make build APP_DIR=./basic-parameter
```

This will compile the app and store it in `tests/target-apps/android/dist/MASTestApp.apk`.

## Installing Target Apps

To install the app follow these steps:

1. **Prepare the target device**

    Make sure the target device (physical Android or iOS device, or an emulator) is up and running and Frida is installed on them.

    For that you need root access to the device. If this is not possible, embed Frida as gadget into the binary. To simplify this process, use [Objection](https://github.com/sensepost/objection).

2. **Install the binary**

    Use the following command to install the generated target app on the running device:

    ```sh
    cd tests/target-apps/android
    make build install
    ```

Now the app can be started by the testing frameworks.
