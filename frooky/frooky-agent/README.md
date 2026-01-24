# Frooky Agent

This is the agent used for frooky. 

You can run it as standalone frida agent as long as you provide
the `hook.ts` file with the instrumentation instructions.

## How to compile the standalone frooky agent

### Install packages

```sh
$ cd frooky-agent/
$ npm install
```

### Build standalone frooky agents

```sh
$ npm run build-ios ../../docs/examples/hooks*.json
$ npm run build-android ../../docs/examples/hooks*.json
```

This will create two files: 

1. `_hooks.ts`: Merged hooks from the JSON files
1. `_agent.ts`: frooky agent which can be run with frida

## Development workflow 

To continuously recompile on change, keep this running in a terminal:

```sh
$ npm run watch-ios ../../docs/examples/hooks*.json
$ npm run watch-android ../../docs/examples/hooks*.json
```

Now you can use frida to run the compiled agent:

```sh
$ frida -U -f org.owasp.mastestapp -l _agent.js
```

The agent will update when you change the code, but also the JSON hook files.

And use an editor like Visual Studio Code for code completion and instant type-checking feedback.
