import type { DecodedValue } from "../../shared/decoders/decodedValue";
import type { NativeParam } from "../decoders/nativeDecodableTypes";
import { NativeDecoder } from "../decoders/nativeDecoder";
import { NativeHookEvent } from "../event/nativeHookEvent";
import { NativeHook } from "./nativeHook";

export function buildNativeStackTrace(ctx: CpuContext, limit: number): string[] {
  const stackTrace: string[] = [];
  try {
    const btFull = Thread.backtrace(ctx, Backtracer.FUZZY);
    for (let i = 0; i < limit; i++) {
      try {
        stackTrace.push(DebugSymbol.fromAddress(btFull[i]).toString());
      } catch (e) {
        frooky.log.error(`Error during stack trace capture: ${e}`);
      }
    }
  } catch (e) {
    frooky.log.warn(`Native backtrace unavailable: ${e}`);
  }
  return stackTrace;
}

export function decodeNativeArgs(args: NativePointer[], params: NativeParam[]): DecodedValue[] {
  const decodedArgs: DecodedValue[] = [];
  if (params.length > 0) {
    params.forEach((param: NativeParam, i: number) => {
      decodedArgs.push(NativeDecoder.decode(args[i], param));
    });
  }
  return decodedArgs;
}

export function buildAndDispatchEvent(hook: NativeHook, decodedArgs: DecodedValue[], returnValue: DecodedValue, stackTrace: string[]): void {
  const event = new NativeHookEvent(hook.moduleName, hook.symbolName);
  event.stackTrace = stackTrace;
  event.args = decodedArgs;
  event.returnValue = returnValue;
  frooky.addEvent(event);
}
