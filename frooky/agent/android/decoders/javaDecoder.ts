import type Java from "frida-java-bridge";
import type { DecodedValue, Decoder } from "../../shared/decoders/decoder";
import type { Param } from "../../shared/hook/parameter";
import { getJavaInstanceDecoder } from "./registry";

export const JavaDecoder: Decoder = {
  decode: (input: Java.Wrapper, param: Param): DecodedValue => {
    const javaScriptType = typeof input;
    if (javaScriptType === "object") {
      // test for frida arrays like "[Ljava.lang.String", "[Z", "[I" etc. or the primitive long java type which is an object in javascript
      if (param.type[0] === "[" || param.type === "long") {
        return {
          type: param.type,
          name: param.name,
          value: input,
        };
      } else {
        // decode complex java instances like "java.util.Set", "java.util.Map", "my.custom.class" etc.
        return getJavaInstanceDecoder(param.type).decode(input, param);
      }
    } else {
      // primitive java type AND java.lang.String already converted to matching javascript type
      return {
        type: param.type,
        name: param.name,
        value: input,
      };
    }
  },
};
