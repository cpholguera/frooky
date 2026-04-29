import type { BaseDecoder } from "../../shared/decoders/baseDecoder";
import type { DecodedValue } from "../../shared/decoders/decodedValue";
import { NativeParam } from "./nativeDecodableTypes";

export const NativeFallbackDecoder: BaseDecoder<NativePointer, NativeParam> = {
  decode: (value, param): DecodedValue => {
    return {
      type: param.type,
      name: param.name,
      value: value.toString(),
    };
  },
};
