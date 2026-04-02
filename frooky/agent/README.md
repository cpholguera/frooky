# Frooky Agent

```txt
   ___    ____           
  / __\  / _  |    _     _    _  _   _   _
 / _\   | (_) |  / _ \ / _ \ | / /  | | | |
/ /     / / | | | (_) | (_) ||  <   | |_| |
\/     /_/  |_|  \___/ \___/ |_|\_\  \__, |
                                     |___/
```


> [!NOTE]
> If you want to learn how to write frooky hooks, please refer to the [documentation of form the frooky host](https://github.com/cpholguera/frooky).



# General Information

At the moment, the frooky agent is not intended to be used by itself or as a library for other frida scripts. 

But if you would like to write your own frooky host, or embed the agent into an existing one, this chapter explains how to send and receive data from and to the agent.

There are two modes you can use the agent:

1. **Host**

    This version requires a custom host application which sends the hook file to the agent using `rpc`.
   
2. **Standalone**
   
    In this version, the hooks will be embedded into the JavaScript agent during the build process. This version can be used directly with `frida` and does not require a custom host. It is mostly intended for development purposes.


# Compile the frooky Agent for a Custom Host

1. **Install all dependencies**

    ```sh
    npm install
    ```

1. **Compile the development standalone client**

    For compressed code use:

    ```sh
    npm run build:prod:android hook.yaml
    npm run build:prod:ios hook.yaml
    ```

    For uncompressed code use:

    ```sh
    npm run build:dev:android hook.yaml
    npm run build:dev:ios hook.yaml
    ```

    This will compile the frooky agent and saves the compiled agents in `./dist/agent-android.js` and `./dist/agent-ios.js`.


1. **Use the frooky agent in your application**


    After you loading the script, you have to send the hook file in the form of a JSON object in the parameter `target` to the agent using the following `rpc` call:

    ```javascript
    rpc.exports = {
        runFrookyAgent(target: any) {
            runFrookyAgent(target)
        }
    };
    ```

## Compile And Run the frooky Standalone Agent

If you want to work on the frooky agent itself, you can also use [`frida`](https://frida.re/) as host.

Follow these steps to do that:

1. **Install all dependencies**

    ```sh
    npm install
    ```

1. **Compile the development standalone client**

    ```sh
    npm run build:watch:android hook.yaml
    npm run build:watch:ios hook.yaml
    ```

    You can specify one or more `hook.yaml` files. Pattern expansion (`glob`) is supported.

    This will compile a development build of the frooky agent, watch for changes in its source code and all `hook.yaml` files, and keep the compiled agents in the `./dist` folder up to date.

1. **Start Frida with the compiled agent**
   
    For Android:

    ```sh
    frida -U -f org.owasp.mytargetapp dist/agent-android.js
    ```

    For iOS:

    ```sh
    frida -U -f org.owasp.mytargetapp dist/agent-ios.js
    ```


