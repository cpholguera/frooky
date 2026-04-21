import { DecodedValue } from "../decoders/decoder";
import { NativeDecoder } from "../decoders/nativeDecoder";
import { Param } from "./parameter";

export function buildNativeStackTrace(ctx: CpuContext, limit: number): string[] {
  const stackTrace: string[] = [];
      try {
        const btFull = Thread.backtrace(ctx, Backtracer.FUZZY);
        for (let i = 0; i < btFull.length; i++) {
          try {
            stackTrace.push(DebugSymbol.fromAddress(btFull[i]).toString());
          } catch (e) {
            stackTrace.push(btFull[i].toString());
          }
        }
      } catch (e) {
        frooky.log.warn("Native backtrace unavailable: " + e + "");
      }
  return stackTrace;
}


export function decodeNativeArgs(args: InvocationArguments, params: Param[]): DecodedValue[]{
  if (args.length === 0) {
    throw Error("Empty args passed");
  }
  if (args.length !== params?.length) {
    throw Error("The actual argument length does not match the declared frooky parameter length");
  }
  const decodedArgs: DecodedValue[] = [];
  try {
    args.forEach((arg: NativePointer, i: number) => {
      decodedArgs.push(NativeDecoder.decode(arg, params[i]));
    });
  } catch (e) {
    frooky.log.error(`Error decoding input parameter: ${e}`);
  }
  return decodedArgs;

}