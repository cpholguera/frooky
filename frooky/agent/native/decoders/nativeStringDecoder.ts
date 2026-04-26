import { NativeParam } from "../hook/nativeParam";
import { BaseDecoder, DecodedValue } from "../../shared/decoders/baseDecoder";

export const NativeStringDecoder: BaseDecoder<NativePointer, NativeParam> = {
  decode: (input: NativePointer, param: NativeParam): DecodedValue => {
      return {
        type: param.type,
        name: param.name,
        value: input.readCString(),
      };
  },
};
