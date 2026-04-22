import type { DecodedValue, Decoder } from "../../shared/decoders/decoder";
import type { Param } from "../../shared/hook/parameter";

export const NativeDecoder: Decoder<NativePointer> = {
  decode: (input: NativePointer, param: Param, quickDecode = false): DecodedValue => {
    console.log("NATIVE DECODER: ")
    console.log(JSON.stringify(param, null, 2))
    // Null input: no resolution needed, don't cache (we have no type signal)
    if (input == null) {
      return { type: param.implementationType ?? param.type, name: param.name, value: null };
    }

    // a decoder was already resolved for this Param
    const cached = param.decoder;
    if (cached) {
      return cached.decode(input, param);
    }
    

    return { type: "void", value: null };

    // // Try to guess the type at runtime and return
    // if (!quickDecode){
    //   const decoder = resolveDecoder(input, param);
    //   param.decoder = decoder;
    //   return decoder.decode(input, param);
    // }
  },
};
