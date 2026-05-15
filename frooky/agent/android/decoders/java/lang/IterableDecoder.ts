// iterableDecoder.ts
import type Java from "frida-java-bridge";
import { Decoder } from "../../../../shared/decoders/baseDecoder";
import { DecodedValue } from "../../../../shared/decoders/decodedValue";
import { DEFAULT_DECODER_SETTINGS } from "../../../../shared/defaultValues";
import { JavaDecoderResolver } from "../../javaDecoderResolver";

/**
 * Decode any java.lang.Iterable by walking its iterator().
 */
export class IterableDecoder extends Decoder<Java.Wrapper> {
  decode(value: Java.Wrapper): DecodedValue {
    const values: DecodedValue[] = [];
    let iterator: Java.Wrapper;
    iterator = value.iterator();
    const decodeLimit = this.decodable.settings.decodeLimit ?? DEFAULT_DECODER_SETTINGS.decodeLimit;

    let iteratorDecoder: Decoder<Java.Wrapper> | undefined;

    let count = 0;
    while (iterator.hasNext() && count < decodeLimit) {
      const element = iterator.next();

      if (!iteratorDecoder) {
        iteratorDecoder = JavaDecoderResolver.resolveDecoder({
          type: element.$className,
          name: this.decodable.name,
          settings: this.decodable.settings,
        });
      }

      values.push(iteratorDecoder.decode(element));
      count++;
    }

    if (iterator.hasNext()) {
      values.push({
        type: "java.lang.String",
        value: `[truncated at ${decodeLimit}]`,
      } as DecodedValue);
    }

    return {
      type: this.decodable.type,
      name: this.decodable.name,
      value: values,
    };
  }
}
