// iterableDecoder.ts
import Java from "frida-java-bridge";
import { DECODER_MAX_ELEMENTS } from "../../../../shared/config";
import type { DecodedValue, Decoder } from "../../../../shared/decoders/decoder";
import type { Param } from "../../../../shared/hook/parameter";
import { JavaDecoder } from "../../javaDecoder";

/**
 * Decode any java.lang.Iterable by walking its iterator().
 */
export function decodeIterable(iterable: Java.Wrapper, param: Param, elementDecoder: (element: Java.Wrapper) => DecodedValue = defaultElementDecoder): DecodedValue {
  const values: DecodedValue[] = [];
  const iterator = iterable.iterator();

  let count = 0;
  while (iterator.hasNext() && count < DECODER_MAX_ELEMENTS) {
    values.push(elementDecoder(iterator.next()));
    count++;
  }

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
}

function defaultElementDecoder(element: Java.Wrapper): DecodedValue {
  const elementType = element == null ? "java.lang.Object" : (element.$className ?? "java.lang.Object");
  return JavaDecoder.decode(element, { type: elementType } as Param);
}

export const java_lang_IterableDecoder: Decoder = {
  decode: (input: Java.Wrapper, param: Param): DecodedValue => {
    const iterable = input.iterator ? input : Java.cast(input, Java.use("java.lang.Iterable"));
    return decodeIterable(iterable, param);
  },
};
