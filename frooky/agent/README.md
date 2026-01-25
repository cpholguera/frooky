# Frooky Agent

This is the agent used by frooky. 

You can run it as standalone frida agent as long as you provide
one or multiple `hook.json` file with the instrumentation instructions.

## How to compile the standalone frooky agent

### Install packages

```sh
$ cd agent/
$ npm install
```

### Build standalone frooky agents

```sh
$ npm run prod-frooky-android"
$ npm run dev-frooky-ios"
```

This will create two files: 

1. `./dist/agent-android.js`: Compressed production build of the frooky agent for android.
1. `./dist/agent-ios.js`: Uncompressed build of the frooky agent for iOS. Better for development.

These agents use the `rpc` API from Frida in order to fetch the `hooks.json` at runtime.

## Development workflow 

I you want to work on the frooky agent code itself, it is recommended using Frida in combination with the following commands:

```sh
$ npm run watch-frida-android ../../docs/examples/hooks*.json
$ npm run watch-frida-ios ../../docs/examples/hooks*.json
```

Now you can use frida to run the compiled agent:

```sh
$ frida -U -f org.owasp.mastestapp -l ./dist/agent-android.js
$ frida -U -f org.owasp.mastestapp -l ./dist/agent-ios.js
```

The agent will update when you change the code, but also the JSON hook files.
