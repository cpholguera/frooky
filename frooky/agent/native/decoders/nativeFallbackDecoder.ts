import { BaseDecoder, DecodedValue } from "../../shared";
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
