import type { BaseDecoder } from "../../shared/decoders/baseDecoder";
import type { DecodedValue } from "../../shared/decoders/decodedValue";
import { NativeDecodableType } from "./nativeDecodableTypes";

export const NativeFallbackDecoder: BaseDecoder<NativePointer, NativeDecodableType> = {
  decode: (value: NativePointer, type: NativeDecodableType): DecodedValue => {
    return {
      type: type.type,
      name: type.name,
      value: value.toString(),
    };
  },
};
