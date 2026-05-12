// iterableDecoder.ts
import type Java from "frida-java-bridge";
import { DecodedValue } from "../../../../shared/decoders/decodedValue";
import { DEFAULT_DECODER_SETTINGS } from "../../../../shared/defaultValues";
import { JavaDecodable } from "../../javaDecodable";
import { JavaDecoderResolver } from "../../javaDecoderResolver";

function defaultElementDecoder(element: Java.Wrapper): DecodedValue {
  const elementType = element == null ? "java.lang.Object" : (element.$className ?? "java.lang.Object");
  // TODO: get the decoder and then decode, but cache it...
  return JavaDecoderResolver.decode(element, { type: elementType, decoderSettings: settings });
}

/**
 * Decode any java.lang.Iterable by walking its iterator().
 */
export function decodeIterable(
  iterable: Java.Wrapper,
  kind: JavaDecodable,
  customElementDecoder?: (entry: Java.Wrapper) => DecodedValue,
): DecodedValue {
  const values: DecodedValue[] = [];
  const iterator = iterable.iterator();
  const limit = kind.decoderSettings.decodeLimit ?? DEFAULT_DECODER_SETTINGS.decodeLimit;

  let count = 0;
  while (iterator.hasNext() && count < limit) {
    const element = iterator.next();
    values.push(customElementDecoder ? customElementDecoder(element) : defaultElementDecoder(element, kind.decoderSettings));
    count++;
  }

  if (iterator.hasNext()) {
    values.push({
      type: "java.lang.String",
      value: `[truncated at ${limit}]`,
    } as DecodedValue);
  }

  return {
    type: kind.implementationType ?? kind.type,
    value: values,
  };
}
