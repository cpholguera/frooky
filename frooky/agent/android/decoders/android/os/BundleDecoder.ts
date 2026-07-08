// iterableDecoder.ts
import type Java from "frida-java-bridge";
import { Decoder } from "../../../../shared/decoders/baseDecoder";
import { DecodedValue } from "../../../../shared/decoders/decodedValue";
import { JavaReferenceTypeDecoder } from "../../javaReferenceTypeDecoder";

/**
 * Decode all key/value pairs form a Bundle
 */
export class BundleDecoder extends Decoder<Java.Wrapper> {
  decode(value: Java.Wrapper): DecodedValue {
    const values: DecodedValue[] = [];
    const keys = value.keySet().toArray();

    for (let i = 0; i < keys.length; i++) {
      const key = keys[i].toString();
      const entry = value.get(key);
      const elementType = entry ? entry.getClass().getName() : "null";

      const decoded = new JavaReferenceTypeDecoder({
        type: elementType,
        name: key,
        settings: this.decodable.settings,
      }).decode(entry);

      values.push({
        type: decoded.type,
        name: key,
        value: (decoded.value as DecodedValue).value,
      });
    }

    return {
      type: this.decodable.type,
      value: values,
    };
  }
}
