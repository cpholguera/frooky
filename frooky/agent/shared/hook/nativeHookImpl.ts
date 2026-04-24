import type { DecodedValue } from "../decoders/decoder";
import { NativeDecoder } from "../decoders/nativeDecoder";
import { NativeHookEvent } from "../event/nativeHookEvent";
import type { NativeHookOp } from "./nativeHookRunner";
import type { NativeParam } from "./nativeParameter";
import type { Param } from "./parameter";

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

export function buildAndDispatchEvent(nativeHookOp: NativeHookOp, decodedArgs: DecodedValue[], returnValue: DecodedValue, stackTrace: string[]): void {
  const event = new NativeHookEvent(nativeHookOp.module, nativeHookOp.symbol);
  event.category = nativeHookOp.category;
  event.stackTrace = stackTrace;
  event.args = decodedArgs;
  event.returnValue = returnValue;
  frooky.addEvent(event);
}
