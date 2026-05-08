import { DecodedValue } from "../../shared/decoders/decodedValue";
import { HOOK_LOOKUP_TIMEOUT_SECONDS } from "../../shared/defaultValues";
import type { HookManager } from "../../shared/hook/hookManager";
import { InputNativeHookNormalized } from "../../shared/inputParsing/inputNativeHookGroup";
import { sleepMilliseconds } from "../../shared/utils";
import { NativeDecoder } from "../decoders/nativeDecoder";
import type { NativeHook } from "./nativeHook";
import { buildAndDispatchEvent, buildNativeStackTrace, decodeNativeArgs } from "./nativeHookImpl";

function resolveSymbol(symbol: string, module: Module): NativePointer {
  try {
    return module.getExportByName(symbol);
  } catch (e) {
    throw Error(`Skipping hook for native function '${symbol}'. This symbol does not exist in module '${module.name}'.`);
  }
}

async function resolveModule(moduleName: string, timeout: number): Promise<Module> {
  frooky.log.info(`Resolving native module ${moduleName} with a timeout of ${timeout} seconds.`);
  const deadline = Date.now() + timeout * 1000;
  while (true) {
    try {
      const module = Process.getModuleByName(moduleName);
      frooky.log.info(`Module '${moduleName}' successfully loaded.`);
      return module;
    } catch (_) {
      // silently ignore errors from Process.getModuleByName
    }
    if (Date.now() >= deadline) {
      throw Error(`Skipping hooks for module '${moduleName}'. The module could not be loaded within a timeout of ${timeout} seconds.`);
    }
    await sleepMilliseconds(HOOK_LOOKUP_TIMEOUT_SECONDS);
  }
}

export class NativeHookManager implements HookManager<InputNativeHookNormalized, NativeHook> {
  registerHook(hook: NativeHook) {
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
    return hook;
  }

  async resolveHooks(inputHooks: InputNativeHookNormalized[], timeout: number): Promise<Promise<NativeHook | null>[]> {
    frooky.log.info(`Resolving native hooks`);

    const uniqueModules: string[] = [...new Map(inputHooks.map((inputHook) => [inputHook.module, inputHook])).keys()];

    return uniqueModules.flatMap((moduleName) => {
      // log once per module, resolve to null on failure
      const modulePromise = resolveModule(moduleName, timeout).catch((e) => {
        frooky.log.warn(`${e}`);
        return null;
      });

      return inputHooks
        .filter((inputHook) => inputHook.module === moduleName)
        .map(async (inputHook): Promise<NativeHook | null> => {
          const resolvedModule = await modulePromise;
          if (!resolvedModule) return null;
          try {
            const symbolAddress = resolveSymbol(inputHook.symbol, resolvedModule);
            frooky.log.info(`Address of function symbol '${inputHook.symbol}' found: ${symbolAddress}.`);
            return {
              module: resolvedModule,
              symbolName: inputHook.symbol,
              symbolAddress,
              params: inputHook.params,
              retType: inputHook.retType,
              hookSettings: inputHook.hookSettings,
              decoderSettings: inputHook.decoderSettings,
            } as NativeHook;
          } catch (e) {
            frooky.log.warn(`${e}`);
            return null;
          }
        });
    });
  }
}
