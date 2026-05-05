import { DecodedValue } from "../../shared/decoders/decodedValue";
import { DEFAULT_HOOK_SETTINGS } from "../../shared/defaultValues";
import { InputNativeHookCanonical } from "../../shared/frookyConfigParsing/nativeHookScope";
import type { HookManager } from "../../shared/hook/hookManager";
import { sleep } from "../../shared/utils";
import { NativeDecoder } from "../decoders/nativeDecoder";
import type { NativeHook } from "./nativeHook";
import { buildAndDispatchEvent, buildNativeStackTrace, decodeNativeArgs } from "./nativeHookImpl";

function registerHook(hook: NativeHook) {
  let stackTrace: string[];
  let decodedArgs: DecodedValue[];
  let decodedReturnValue: DecodedValue;
  Interceptor.attach(hook.symbolAddress, {
    onEnter: function (args: NativePointer[]) {
      // collect the stack trace from Frida
      const stackTraceLimit: number = hook.hookSettings.stackTraceLimit;
      stackTrace = buildNativeStackTrace(this.context, stackTraceLimit);
      // decode the arguments passed to this function
      if (hook.params) {
        decodedArgs = decodeNativeArgs(args, hook.params);
      }
    },
    onLeave: (returnValue: InvocationReturnValue) => {
      // decode the return value
      if (hook.retType) {
        decodedReturnValue = NativeDecoder.decode(returnValue, hook.retType);
      } else {
        decodedReturnValue = { type: "void", value: null };
      }
      // create a frooky hook event and send it to the event cache
      buildAndDispatchEvent(hook, decodedArgs, decodedReturnValue, stackTrace);
    },
  });
}

function resolveSymbolName(symbol: string, module: Module): NativePointer {
  try {
    return module.getExportByName(symbol);
  } catch (e) {
    throw Error(`Symbol '${symbol}' does not exist in module '${module}'`);
  }
}

async function resolveModule(moduleName: string, hookTimeoutMs: number): Promise<Module> {
  frooky.log.info(`Trying to load native module ${moduleName} with a timeout of ${hookTimeoutMs}ms.`);
  const deadline = Date.now() + hookTimeoutMs;
  while (true) {
    try {
      return Process.getModuleByName(moduleName);
    } catch (_) {
      // silently ignore errors from Process.getModuleByName
    }
    if (Date.now() >= deadline) {
      throw new Error(`Module '${moduleName}' could not be loaded within ${hookTimeoutMs}ms. It either does not exist, or is not loaded yet.`);
    }
    await sleep(100);
  }
}

export class NativeHookResolver implements HookManager<InputNativeHookCanonical, NativeHook> {
  registerHooks(hooks: NativeHook[]) {
    console.log("aaaaaaaaaaaaaaaa");
    for (const hook of hooks) {
      registerHook(hook);
    }
  }
  async resolveInputHooks(inputHooks: InputNativeHookCanonical[]): Promise<NativeHook[]> {
    frooky.log.info(`Resolving native hooks`);

    const promises = inputHooks.map(async (inputHook) => {
      const hookTimeoutMs = inputHook.hookSettings?.hookTimeoutMs ?? DEFAULT_HOOK_SETTINGS.hookTimeoutMs;
      try {
        const module = await resolveModule(inputHook.moduleName, hookTimeoutMs);
        const symbolAddress = resolveSymbolName(inputHook.symbolName, module);
        return {
          moduleName: inputHook.moduleName,
          module,
          symbolName: inputHook.symbolName,
          symbolAddress,
          params: inputHook.params,
          retType: inputHook.retType,
          hookSettings: inputHook.hookSettings,
          decoderSettings: inputHook.decoderSettings,
        } as NativeHook;
      } catch (e) {
        frooky.log.error(String(e));
        return null;
      }
    });

    return Promise.all(promises).then((results) => results.filter((r): r is NativeHook => r !== null));
  }
}
