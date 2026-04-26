import type { DecodedValue } from "./decodedValue";

export interface BaseDecoder<TInput, TParam> {
  // decodes an input value,
  // param contains additional information about the value such as name or type
  // quickDecode is an optional flag, if set, we TRY to minimize Frida <-> Bridge <-> Platform calls
  // at cost of less information.
  decode: (input: TInput, param: TParam, quickDecode?: boolean) => DecodedValue;
}
