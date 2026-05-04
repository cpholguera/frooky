import { DEFAULT_HOOK_SETTINGS } from "../../shared/defaultValues";
import { InputNativeHookCanonical } from "../../shared/frookyConfigParsing/nativeHookScope";
import type { HookResolver } from "../../shared/hook/hookResolver";
import { sleep } from "../../shared/utils";
import type { NativeHook } from "./nativeHook";

// actually hooks the native function
// export function registerNativeHookOps(nativeHook: NativeHook) {
// let stackTrace: string[];
// let decodedArgs: DecodedValue[];
// let decodedReturnValue: DecodedValue;
// Interceptor.attach(nativeHookOp.symbolAddress, {
//   onEnter: function (args: NativePointer[]) {
//     // collect the stack trace from Frida
//     const stackTraceLimit: number = nativeHookOp.hookSettings?.stackTraceLimit ? nativeHookOp.hookSettings?.stackTraceLimit : DEFAULT_HOOK_SETTINGS.stackTraceLimit;
//     stackTrace = buildNativeStackTrace(this.context, stackTraceLimit);
//     // decode the arguments passed to this function
//     decodedArgs = decodeNativeArgs(args, nativeHookOp.params);
//   },
//   onLeave: (returnValue: InvocationReturnValue) => {
//     // decode the return value
//     if (nativeHookOp.retType) {
//       decodedReturnValue = NativeDecoder.decode(returnValue, nativeHookOp.retType);
//     } else {
//       decodedReturnValue = { type: "void", value: null };
//     }
//     // create a frooky hook event and send it to the event cache
//     buildAndDispatchEvent(nativeHookOp, decodedArgs, decodedReturnValue, stackTrace);
//   },
// });
// }

function resolveSymbolName(symbol: string, module: Module): NativePointer {
  try {
    return module.getExportByName(symbol);
  } catch (e) {
    throw Error(`Symbol '${symbol}' does not exist in module '${module}'`);
  }
}

async function resolveModule(moduleName: string, hookTimeoutMs: number): Promise<Module> {
  const deadline = Date.now() + hookTimeoutMs;
  while (true) {
    try {
      return Process.getModuleByName(moduleName);
    } catch (e) {
      frooky.log.warn(String(e));
    }
    if (Date.now() >= deadline) {
      throw new Error(`Module '${moduleName}' could not be loaded within ${hookTimeoutMs}ms.`);
    }
    await sleep(100);
  }
}

export class NativeHookResolver implements HookResolver<InputNativeHookCanonical, NativeHook> {
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
