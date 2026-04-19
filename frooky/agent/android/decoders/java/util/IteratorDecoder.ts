import Java from "frida-java-bridge";
import { DECODER_MAX_ELEMENTS } from "../../../../shared/config";
import type { DecodedValue, Decoder } from "../../../../shared/decoders/decoder";
import type { Param } from "../../../../shared/hook/parameter";
import { JavaDecoder } from "../../javaDecoder";

export const IteratorDecoder: Decoder = {
  decode: (input: Java.Wrapper, param: Param): DecodedValue => {
    const values: DecodedValue[] = [];
    const iterable = input.iterator ? input : Java.cast(input, Java.use("java.lang.Iterable"));
    const iterator = iterable.iterator();

    let count = 0;
    while (iterator.hasNext() && count < DECODER_MAX_ELEMENTS) {
      const element = iterator.next();
      const elementType = element == null ? "java.lang.Object" : (element.$className ?? "java.lang.Object");

      values.push(JavaDecoder.decode(element, { type: elementType } as Param));
      count++;
    }

    // flag truncation
    if (iterator.hasNext()) {
      values.push({
        type: "java.lang.String",
        value: `[truncated at ${DECODER_MAX_ELEMENTS}]`,
      } as DecodedValue);
    }

    return {
      type: param.type,
      name: param.name,
      value: values,
    };
  },
};
