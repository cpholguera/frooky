import Java from "frida-java-bridge";
import { Decoder } from "../../../../shared/decoders/baseDecoder";
import { DecodedValue } from "../../../../shared/decoders/decodedValue";
import { JavaDecodable } from "../../javaDecodable";
import { JavaDecoderResolver } from "../../javaDecoderResolver";
import { decodeIterable } from "../lang/IterableDecoder";

export class MapDecoder extends Decoder<JavaDecodable, Java.Wrapper> {
  decode(value) {
    const map = value.entrySet ? value : Java.cast(value, Java.use("java.util.Map"));
    const entrySet = map.entrySet();

    // Cache the Map. Entry class once per call
    const MapEntry = Java.use("java.util.Map$Entry");

    return decodeIterable(entrySet, this.kind, (entry) => {
      const typedEntry = entry!.getKey ? entry! : Java.cast(entry!, MapEntry);

      const key = typedEntry.getKey();
      const value = typedEntry.getValue();

      const keyType = key == null ? "java.lang.Object" : (key.$className ?? "java.lang.Object");
      const valueType = value == null ? "java.lang.Object" : (value.$className ?? "java.lang.Object");

      return {
        type: "java.util.Map.Entry",
        value: [
          // TODO: get the decoder and then decode
          { ...JavaDecoderResolver.decode(key, { type: keyType, decoderSettings: this.kind.decoderSettings }), name: "key" },
          { ...JavaDecoderResolver.decode(value, { type: valueType, decoderSettings: this.kind.decoderSettings }), name: "value" },
        ],
      } as DecodedValue;
    });
  }
}
