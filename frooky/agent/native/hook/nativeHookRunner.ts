import { DEFAULT_DECODER_SETTINGS, DEFAULT_HOOK_SETTINGS } from "../../shared/config";
import type { RetType } from "../../shared/decoders/decodableTypes";
import type { DecodedValue } from "../../shared/decoders/decodedValue";
import type { HookOp, HookRunner } from "../../shared/hook/hookRunner";
import { retryUntilSuccess } from "../../shared/utils";
import { validateAndRepairDecoderSettings } from "../../shared/validator/configValidator";
import type { NativeParam } from "../decoders/nativeDecodableTypes";
import { NativeDecoder } from "../decoders/nativeDecoder";
import type { NativeFrookyFunction, NativeHook } from "./nativeHook";
import { buildAndDispatchEvent, buildNativeStackTrace, decodeNativeArgs } from "./nativeHookImpl";

export interface NativeHookOp extends HookOp {
  module: string;
  symbol: string;
  symbolAddress: NativePointer;
  params: NativeParam[];
  retType: RetType;
}

// actually hooks the native function
export function registerNativeHookOps(nativeHookOp: NativeHookOp) {
  let stackTrace: string[];
  let decodedArgs: DecodedValue[];
  let decodedReturnValue: DecodedValue;

  Interceptor.attach(nativeHookOp.symbolAddress, {
    onEnter: function (args: NativePointer[]) {
      // collect the stack trace from Frida
      const stackTraceLimit: number = nativeHookOp.hookSettings?.stackTraceLimit ? nativeHookOp.hookSettings?.stackTraceLimit : DEFAULT_HOOK_SETTINGS.stackTraceLimit;
      stackTrace = buildNativeStackTrace(this.context, stackTraceLimit);
      // decode the arguments passed to this function
      decodedArgs = decodeNativeArgs(args, nativeHookOp.params);
    },
    onLeave: (returnValue: InvocationReturnValue) => {
      // decode the return value
      if (nativeHookOp.retType) {
        decodedReturnValue = NativeDecoder.decode(returnValue, nativeHookOp.retType);
      } else {
        decodedReturnValue = { type: "void", value: null };
      }
      // create a frooky hook event and send it to the event cache
      buildAndDispatchEvent(nativeHookOp, decodedArgs, decodedReturnValue, stackTrace);
    },
  });
}

// builds a list of native hook operations. Each NativeHookOp contains all information to hook ONE native function
async function buildNativeHookOps(hook: NativeHook): Promise<NativeHookOp[]> {
  const nativeHHookOps: NativeHookOp[] = [];
  // TODO: Load all modules in one timeout instead of each one. At the moment, each typo adds one timeout.

  let module: Module;
  try {
    frooky.log.info(`Trying to load the module '${hook.module}' with a timeout of ${hook.hookSettings.hookTimeout}ms.`);
    await retryUntilSuccess(
      () => {
        module = Process.getModuleByName(hook.module);
      },
      100,
      hook.hookSettings.hookTimeout,
    );
  } catch (e) {
    frooky.log.error(`Module ${hook.module} could not be loaded within ${hook.hookSettings.hookTimeout}ms. Module '${hook.module}' does not exist, or did not load within the timeout.`);
    return nativeHHookOps;
  }

  hook.functions.forEach((fn: NativeFrookyFunction) => {
    let symbolAddress: NativePointer;
    try {
      symbolAddress = module.getExportByName(fn.symbol);
    } catch (e) {
      frooky.log.error(`Symbol '${fn.symbol}' does not exist in module '${module}'`);
      return;
    }

    if (fn.retType?.settings) {
      fn.retType.settings = validateAndRepairDecoderSettings({ ...DEFAULT_DECODER_SETTINGS, ...fn.retType?.settings });
    }

    nativeHHookOps.push({
      hookSettings: hook.hookSettings,
      decoderSettings: validateAndRepairDecoderSettings({ ...DEFAULT_DECODER_SETTINGS, ...hook.decoderSettings }),
      module: hook.module,
      symbol: fn.symbol,
      symbolAddress: symbolAddress,
      params: fn.params ?? [],
      retType: fn.retType ?? { type: "void", settings: DEFAULT_DECODER_SETTINGS },
    });
  });
  return nativeHHookOps;
}

export class NativeHookRunner implements HookRunner {
  async executeHooking(hooks: NativeHook[]): Promise<void> {
    const nativeHookOps: NativeHookOp[] = [];

    frooky.log.info(`Executing native hook operations`);
    for (const h of hooks) {
      frooky.log.info(`Building hook operations for native`);
      nativeHookOps.push(...(await buildNativeHookOps(h)));
    }

    frooky.log.info(`Run native hooking`);
    nativeHookOps.forEach((nativeHookOp: NativeHookOp) => {
      registerNativeHookOps(nativeHookOp);
    });
  }
}
