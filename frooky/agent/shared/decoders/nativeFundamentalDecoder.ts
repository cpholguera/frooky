import type { Param } from "../hook/parameter";
import type { DecodedValue, Decoder } from "./decoder";

export const NativeFundamentalDecoder: Decoder<NativePointer> = {
  decode: (input: NativePointer, param: Param): DecodedValue => {
    return {
      type: param.type,
      name: param.name,
      value: input.toInt32(),
    };
  },
};
