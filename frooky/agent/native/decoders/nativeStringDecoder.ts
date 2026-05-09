import { BaseDecoder } from "../../shared/decoders/baseDecoder";
import { DecodedValue } from "../../shared/decoders/decodedValue";
import { NativeDecodableType } from "./nativeDecodableTypes";

export const NativeStringDecoder: BaseDecoder<NativePointer, NativeDecodableType> = {
  decode: (value: NativePointer, type: NativeDecodableType): DecodedValue => {
    return {
      type: type.type,
      name: type.name,
      value: value.readCString(),
    };
  },
};
