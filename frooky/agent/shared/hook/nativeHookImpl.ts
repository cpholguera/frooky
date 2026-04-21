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




export function decodeNativeArgs(args: InvocationArguments, params: Param[]){

}