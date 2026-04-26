import type { NativeParam } from "../hook/nativeParam";
import type { BaseDecoder, DecodedValue } from "../../shared/decoders/baseDecoder";

export const NativeFallbackDecoder: BaseDecoder<NativePointer, NativeParam> = {
  decode: (input: NativePointer, param: NativeParam): DecodedValue => {
    return {
      type: param.type,
      name: param.name,
      value: input.toString(),
    };
  },
};
