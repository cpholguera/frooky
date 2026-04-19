import type Java from "frida-java-bridge";
import type { Decoder } from "../../shared/decoders/decoder";
import type { Param } from "../../shared/hook/parameter";

export const javaDecoder: Decoder = {
  decode: (input: Java.Field, param: Param) => {
    if (!param.decoder) {
      // lookup the decoder

      console.log("DECODER");
      console.log(JSON.stringify(param, null, 2));
      console.log(typeof input);
      console.log(JSON.stringify(input, null, 2));
      return { value: input.toString() };
    } else {
      return param.decoder.decode();
    }
  },
};
