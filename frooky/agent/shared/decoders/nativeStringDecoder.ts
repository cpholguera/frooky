import { NativeParam } from "../hook/nativeParameter";
import { BaseDecoder, DecodedValue } from "./baseDecoder";

export const NativeStringDecoder: BaseDecoder<NativePointer, NativeParam> = {
  decode: (input: NativePointer, param: NativeParam): DecodedValue => {
      return {
        type: param.type,
        name: param.name,
        value: input.readCString(),
      };
  },
};
