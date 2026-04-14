# Target Apps

Frooky uses target apps for testing features that must run in a real runtime environment. Some behavior is only available on the actual operating system and cannot be reproduced reliably from the host OS (e.g. macOS) alone. Type decoders are one example, since they should be validated against real Android or iOS implementations.

## Building Target Apps

These apps are located in the folder `tests/target-apps/<android|ios>/`. They must be in the form of a [MASTG-DEMO app](https://mas.owasp.org/MASTG/demos/). For iOS the base app is [`mas-app-ios`](https://github.com/cpholguera/mas-app-ios) and for Android [`mas-app-android`](https://github.com/cpholguera/mas-app-android)

Make sure, that you have all the prerequisites met to compile Android or iOS apps. For Android, you need to install [Android Studio](https://developer.android.com/studio), for iOS [Xcode](https://developer.apple.com/xcode/).

To compile them, go to either `tests/target-apps/<android|ios>/` and run:

- `make build TARGET_APP=<target-app>` to build a custom app.
- `make build-all` to build all apps in their subfolder.

> [!IMPORTANT]
> The package name or app identifier is always `<target-app>`.

This will compile the app with the app identifier `<target-app>` and store it in `tests/target-apps/ios/dist/<target-app>.app` for iOS and `tests/target-apps/android/dist/<target-app>.apk` for Android.

**Example 1:** Build a custom app based on `mas-app-android`:

```sh
cd tests/target-apps/android
make build TARGET_APP=basic-parameter
```

This will compile the app with the package name `basic_parameter.target_app` and store it in `tests/target-apps/android/dist/basic-parameter.apk`.

**Example 2:** Build all apps:

```sh
cd tests/target-apps/ios
make build-all
```

This will compile the app with the package name `basic-parameter.org.owasp.mastestapp` and store it in `tests/target-apps/android/dist/<target-app-name>.target-app.apk`.

## Installing Target Apps

To install the app follow these steps:

1. **Prepare the target device**

    Make sure the target device (physical Android or iOS device, or an emulator) is up and running and Frida is installed on them.

    For that you need root access to the device. If this is not possible, embed Frida as gadget into the binary. To simplify this process, use [Objection](https://github.com/sensepost/objection).

2. **Install the binary**

    Use the following command to install a generated target app on the running device:

    ```sh
    cd tests/target-apps/android
    make install TARGET_APP=<target-app-dir>
    ```

    You can also install all apps using the following command:

    ```sh
    cd tests/target-apps/android
    make install-all
    ```

Now the app can be started by the testing frameworks.
