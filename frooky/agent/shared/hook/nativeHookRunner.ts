import type { NativeFunctionDefinition, NativeHook, Param, SymbolName } from "frooky";
import { registerNativeHooks } from "../../android/legacy/android-agent";
import { DEFAULT_STACK_TRACE_LIMIT } from "../config";
import type { HookOp, HookRunner } from "./hookRunner";

export interface NativeHookOp extends HookOp {
  symbol: SymbolName;
  symbolAddress: NativePointer;
  params: Param[];
}

// builds a list of native hook operations. Each NativeHookOp contains all information to hook ONE java method
function buildNativeHookOps(hook: NativeHook): NativeHookOp[] {
  const nativeHHookOps: NativeHookOp[] = [];
  try {
    const module = Process.getModuleByName(hook.module);

    hook.functions.forEach((fn: NativeFunctionDefinition) => {
      try {
        nativeHHookOps.push({
          stackTraceLimit: hook.stackTraceLimit ?? DEFAULT_STACK_TRACE_LIMIT,
          module: hook.module,
          symbol: fn.symbol,
          symbolAddress: module.getExportByName(fn.symbol),
          params: [],
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
    registerNativeHooks(nativeHookOps);
  }
}
