import type { NativeFrookyFunctionDefinition, NativeHook, Param, SymbolName } from "frooky";
import { DEFAULT_STACK_TRACE_LIMIT } from "../config";
import type { DecodedValue } from "../decoders/decoder";
import { NativeDecoder } from "../decoders/nativeDecoder";
import type { HookOp, HookRunner } from "./hookRunner";
import { buildAndDispatchEvent, buildNativeStackTrace, decodeNativeArgs } from "./nativeHookImpl";

export interface NativeHookOp extends HookOp {
  module: string;
  symbol: SymbolName;
  symbolAddress: NativePointer;
  returnType: Param;
  params: Param[];
}

// actually hooks the native function
export function registerNativeHookOps(nativeHookOp: NativeHookOp) {
  let stackTrace: string[];
  let decodedArgs: DecodedValue[];
  let decodedReturnValue: DecodedValue;

  Interceptor.attach(nativeHookOp.symbolAddress, {
    onEnter: function (args: NativePointer[]) {
      // collect the stack trace from Frida
      stackTrace = nativeHookOp.stackTraceLimit > 0 ? buildNativeStackTrace(this.context, nativeHookOp.stackTraceLimit) : [];
      // decode the arguments passed to the method
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

// builds a list of native hook operations. Each NativeHookOp contains all information to hook ONE java method
function buildNativeHookOps(hook: NativeHook): NativeHookOp[] {
  const nativeHHookOps: NativeHookOp[] = [];
  try {
    const module = Process.getModuleByName(hook.module);

    hook.functions.forEach((fn: NativeFrookyFunctionDefinition) => {
      try {
        nativeHHookOps.push({
          stackTraceLimit: hook.stackTraceLimit ?? DEFAULT_STACK_TRACE_LIMIT,
          module: hook.module,
          symbol: fn.symbol,
          symbolAddress: module.getExportByName(fn.symbol),
          params: fn.params ?? [],
          returnType: fn.returnType ?? { type: "void" },
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
    console.log("execute Hooking ");
    console.log(JSON.stringify(hooks, null, 2));
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
