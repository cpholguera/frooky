// iterableDecoder.ts
import Java from "frida-java-bridge";
import { DECODER_MAX_ELEMENTS } from "../../../../shared/config";
import type { BaseDecoder, DecodedValue } from "../../../../shared/decoders/baseDecoder";
import type { Param } from "../../../../shared/hook/parameter";
import type { JavaParam } from "../../../hook/javaParameter";
import { JavaDecoder } from "../../javaDecoder";

/**
 * Decode any java.lang.Iterable by walking its iterator().
 */
export function decodeIterable(iterable: Java.Wrapper, param: JavaParam, elementDecoder: (element: Java.Wrapper) => DecodedValue = defaultElementDecoder): DecodedValue {
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
    type: param.implementationType ?? param.type,
    name: param.name,
    value: values,
  };
}

function defaultElementDecoder(element: Java.Wrapper): DecodedValue {
  const elementType = element == null ? "java.lang.Object" : (element.$className ?? "java.lang.Object");
  return JavaDecoder.decode(element, { type: elementType });
}

export const IterableDecoder: BaseDecoder<Java.Wrapper, JavaParam> = {
  decode: (input: Java.Wrapper, param: Param): DecodedValue => {
    const iterable = input.iterator ? input : Java.cast(input, Java.use("java.lang.Iterable"));
    return decodeIterable(iterable, param);
  },
};
