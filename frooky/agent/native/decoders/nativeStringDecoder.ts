import { NativeDecodableType } from "frooky/native";
import { BaseDecoder, DecodedValue } from "frooky/shared";

export const NativeStringDecoder: BaseDecoder<NativePointer, NativeDecodableType> = {
  decode: (value: NativePointer, type: NativeDecodableType): DecodedValue => {
    return {
      type: type.type,
      name: type.name,
      value: value.readCString(),
    };
  },
};
