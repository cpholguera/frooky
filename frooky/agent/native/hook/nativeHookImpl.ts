import { Param } from "../../shared/decoders/decodableTypes";
import { DecodedValue } from "../../shared/decoders/decodedValue";
import { NativeDecodableType } from "../decoders/nativeDecodableTypes";
import { NativeDecoder } from "../decoders/nativeDecoder";
import { NativeHookEvent } from "../event/nativeHookEvent";
import { NativeHook } from "./nativeHook";

export function buildNativeStackTrace(ctx: CpuContext, limit: number): string[] {
  const stackTrace: string[] = [];
  try {
    const btFull = Thread.backtrace(ctx, Backtracer.FUZZY);
    const count = Math.min(limit, btFull.length);
    for (let i = 0; i < count; i++) {
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

export function decodeNativeArgs(args: NativePointer[], params: Param[]): DecodedValue[] {
  const decodedArgs: DecodedValue[] = [];
  if (params.length > 0) {
    params.forEach((param: Param, i: number) => {
      decodedArgs.push(NativeDecoder.decode(args[i], param as NativeDecodableType, param.decoderSettings));
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
