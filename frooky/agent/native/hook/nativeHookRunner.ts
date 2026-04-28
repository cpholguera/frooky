import { DEFAULT_DECODER_SETTINGS, DEFAULT_HOOK_SETTINGS } from "../../shared/config";
import type { DecodedValue } from "../../shared/decoders/decodedValue";
import type { HookOp, HookRunner } from "../../shared/hook/hookRunner";
import { NativeDecoder } from "../decoders/nativeDecoder";
import type { NativeFrookyFunctionDefinition, NativeHook, SymbolName } from "./nativeHook";
import { buildAndDispatchEvent, buildNativeStackTrace, decodeNativeArgs } from "./nativeHookImpl";
import type { NativeParam } from "./nativeParam";

export interface NativeHookOp extends HookOp {
  module: string;
  symbol: SymbolName;
  symbolAddress: NativePointer;
  params: NativeParam[];
  returnType: NativeParam;
}

// actually hooks the native function
export function registerNativeHookOps(nativeHookOp: NativeHookOp) {
  let stackTrace: string[];
  let decodedArgs: DecodedValue[];
  let decodedReturnValue: DecodedValue;

  Interceptor.attach(nativeHookOp.symbolAddress, {
    onEnter: function (args: NativePointer[]) {
      // collect the stack trace from Frida
      const stackTraceLimit: number = nativeHookOp.settings?.stackTraceLimit ? nativeHookOp.settings?.stackTraceLimit : DEFAULT_HOOK_SETTINGS.stackTraceLimit;
      stackTrace = buildNativeStackTrace(this.context, stackTraceLimit);
      // decode the arguments
      // passed to the method
      decodedArgs = decodeNativeArgs(args, nativeHookOp.params);
    },
    onLeave: (returnValue: InvocationReturnValue) => {
      // decode the return value
      if (nativeHookOp.returnType) {
        decodedReturnValue = NativeDecoder.decode(returnValue, nativeHookOp.returnType);
      } else {
        decodedReturnValue = { type: "void", value: null };
      }
      // create a frooky hook event and send it to the event cache
      buildAndDispatchEvent(nativeHookOp, decodedArgs, decodedReturnValue, stackTrace);
    },
  });
}

// builds a list of native hook operations. Each NativeHookOp contains all information to hook ONE native function
function buildNativeHookOps(hook: NativeHook): NativeHookOp[] {
  const nativeHHookOps: NativeHookOp[] = [];
  try {
    const module = Process.getModuleByName(hook.module);

    hook.functions.forEach((fn: NativeFrookyFunctionDefinition) => {
      if (hook.settings?.decoderSettings) {
        fn.params?.forEach((param: NativeParam) => {
          param.options = param.options ?? {};
          param.options.decoderSettings = {
            ...hook.settings?.decoderSettings,
            ...param.options.decoderSettings,
          };
          // add the DEFAULT_DECODER_SETTINGS in case the setting is not yet defined
          param.options.decoderSettings = { ...DEFAULT_DECODER_SETTINGS, ...param.options.decoderSettings };
        });
      }
      try {
        nativeHHookOps.push({
          module: hook.module,
          symbol: fn.symbol,
          settings: hook.settings,
          symbolAddress: module.getExportByName(fn.symbol),
          params: fn.params ?? [],
          returnType: fn.returnType ?? { type: "void", name: undefined },
        });
      } catch (e) {
        frooky.log.error(`Failed to resolve native symbol '${fn.symbol}'${hook.module ? ` in module '${hook.module}'` : ""}: ${e}`);
      }
    });
  } catch (e) {
    frooky.log.error(`Failed to get module '${hook.module}': ${e}`);
  }
  return nativeHHookOps;
}

export class NativeHookRunner implements HookRunner {
  executeHooking(hooks: NativeHook[]): void {
    var nativeHookOps: NativeHookOp[] = [];

    frooky.log.info(`Executing native hook operations`);
    hooks.forEach((h: NativeHook) => {
      frooky.log.info(`Building hook operations for native`);
      nativeHookOps.push(...buildNativeHookOps(h));
    });
    frooky.log.info(`Hook operations for the following hook built: ${JSON.stringify(nativeHookOps, null, 2)}`);
    frooky.log.info(`Run native hooking`);
    nativeHookOps.forEach((nativeHookOp: NativeHookOp) => {
      registerNativeHookOps(nativeHookOp);
    });
  }
}
