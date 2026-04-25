import type { NativeParam } from "../hook/nativeParameter";
import type { Param } from "../hook/parameter";
import type { BaseDecoder, DecodedValue } from "./baseDecoder";

export const NativeFallbackDecoder: BaseDecoder<NativePointer, NativeParam> = {
  decode: (input: NativePointer, param: Param): DecodedValue => {
    return {
      type: param.type,
      name: param.name,
      value: input.toString(),
    };
  },
};
