import type { BaseDecoder } from "../../shared/decoders/baseDecoder";
import type { DecodedValue } from "../../shared/decoders/decodedValue";
import type { NativeParam } from "../hook/nativeParam";

export const NativeStringDecoder: BaseDecoder<NativePointer, NativeParam> = {
  decode: (input: NativePointer, param: NativeParam): DecodedValue => {
    return {
      type: param.type,
      name: param.name,
      value: input.readCString(),
    };
  },
};
