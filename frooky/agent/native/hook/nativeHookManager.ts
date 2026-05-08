import { DecodedValue } from "../../shared/decoders/decodedValue";
import { DEFAULT_HOOK_SETTINGS, FRIDA_LOOKUP_INTERVAL_MS } from "../../shared/defaultValues";
import type { HookManager } from "../../shared/hook/hookManager";
import { InputNativeHookNormalized } from "../../shared/inputParsing/inputNativeHookGroup";
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
        decodedReturnValue = NativeDecoder.decode(returnValue, hook.retType, hook.decoderSettings);
      } else {
        decodedReturnValue = { type: "void", value: null };
      }
      // create a frooky hook event and send it to the event cache
      buildAndDispatchEvent(hook, decodedArgs, decodedReturnValue, stackTrace);
    },
  });
}

function resolveSymbol(symbol: string, module: Module): NativePointer {
  try {
    return module.getExportByName(symbol);
  } catch (e) {
    throw Error(`Symbol '${symbol}' does not exist in module '${module}'`);
  }
}

async function resolveAndCacheModule(moduleName: string, hookTimeoutMs: number): Promise<Module> {
  frooky.log.info(`Loading native module ${moduleName} with a timeout of ${hookTimeoutMs}ms.`);
  const deadline = Date.now() + hookTimeoutMs;
  while (true) {
    try {
      return Process.getModuleByName(moduleName);
    } catch (_) {
      // silently ignore errors from Process.getModuleByName
    }
    if (Date.now() >= deadline) {
      throw new Error(`Sipping hooks for module '${moduleName}' as it could not be loaded during a time out of ${hookTimeoutMs}ms.`);
    }
    await sleep(FRIDA_LOOKUP_INTERVAL_MS);
  }
}

export class NativeHookManager implements HookManager<InputNativeHookNormalized, NativeHook> {
  private resolvedModules: Record<string, Module> = {};

  registerHooks(hooks: NativeHook[]) {
    for (const hook of hooks) {
      registerHook(hook);
    }
  }
  async resolveHooks(inputHooks: InputNativeHookNormalized[]): Promise<NativeHook[]> {
    frooky.log.info(`Resolving native hooks`);

    const promises = inputHooks.map(async (inputHook) => {
      const hookTimeoutMs = inputHook.hookSettings?.hookTimeoutMs ?? DEFAULT_HOOK_SETTINGS.hookTimeoutMs;
      try {
        const module = await resolveAndCacheModule(inputHook.module!, hookTimeoutMs);
        const symbolAddress = resolveSymbol(inputHook.symbol, module);
        return {
          module: module,
          symbolName: inputHook.symbol,
          symbolAddress,
          params: inputHook.params,
          retType: inputHook.retType,
          hookSettings: inputHook.hookSettings,
          decoderSettings: inputHook.decoderSettings,
        } as NativeHook;
      } catch (e) {
        frooky.log.warn(`${e}`);
      }
    });

    return Promise.all(promises).then((nativeHook) => nativeHook.filter((r): r is NativeHook => r !== null));
  }
}
