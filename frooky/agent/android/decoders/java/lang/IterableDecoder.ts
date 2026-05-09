// iterableDecoder.ts
import type Java from "frida-java-bridge";
import { DecodedValue, DecoderSettings, DEFAULT_DECODER_SETTINGS } from "../../../../shared";
import { JavaParam } from "../../../hook/javaParam";
import { JavaDecoder } from "../../javaDecoder";

function defaultElementDecoder(element: Java.Wrapper, settings: DecoderSettings): DecodedValue {
  const elementType = element == null ? "java.lang.Object" : (element.$className ?? "java.lang.Object");
  return JavaDecoder.decode(element, { type: elementType, decoderSettings: settings });
}

/**
 * Decode any java.lang.Iterable by walking its iterator().
 */
export function decodeIterable(iterable: Java.Wrapper, param: JavaParam, customElementDecoder?: (entry: Java.Wrapper) => DecodedValue): DecodedValue {
  const values: DecodedValue[] = [];
  const iterator = iterable.iterator();
  const limit = param.decoderSettings.decodeLimit ?? DEFAULT_DECODER_SETTINGS.decodeLimit;

  let count = 0;
  while (iterator.hasNext() && count < limit) {
    const element = iterator.next();
    values.push(customElementDecoder ? customElementDecoder(element) : defaultElementDecoder(element, param.decoderSettings));
    count++;
  }

  if (iterator.hasNext()) {
    values.push({
      type: "java.lang.String",
      value: `[truncated at ${limit}]`,
    } as DecodedValue);
  }

  return {
    type: param.implementationType ?? param.type,
    name: param.paramNname,
    value: values,
  };
}
