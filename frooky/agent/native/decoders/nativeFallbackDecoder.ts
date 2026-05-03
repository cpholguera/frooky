import type { BaseDecoder } from "../../shared/decoders/baseDecoder";
import type { DecodedValue } from "../../shared/decoders/decodedValue";
import type { NativeParam } from "./nativeDecodableTypes";

export const NativeFallbackDecoder: BaseDecoder<NativePointer, NativeParam> = {
  decode: (value, param): DecodedValue => {
    return {
      type: param.type,
      name: param.paramNname,
      value: value.toString(),
    };
  },
};
