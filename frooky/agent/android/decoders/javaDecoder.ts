import type { Decoder } from "../../shared/decoders/decoder";
import type { Param } from "../../shared/hook/parameter";

export const javaDecoder: Decoder = {
  decode: (input: unknown, param: Param) => {
    const javaScriptType = typeof input;
    if (javaScriptType === "object") {
      // test for the primitive long type
      if (param.type === "long") {
        return {
          type: param.type,
          name: param.name,
          value: input,
        };
      } else {
        // decode complex java type
        return {
          type: param.type,
          name: param.name,
          value: input,
        };
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
