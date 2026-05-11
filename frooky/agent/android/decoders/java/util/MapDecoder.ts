import Java from "frida-java-bridge";
import { Decoder } from "../../../../shared/decoders/baseDecoder";
import { JavaParam } from "../../../hook/javaParam";
import { JavaDecoder } from "../../javaDecoder";
import { decodeIterable } from "../lang/IterableDecoder";

export const MapDecoder: Decoder<Java.Wrapper, JavaParam> = {
  decode: (value, param) => {
    const map = value.entrySet ? value : Java.cast(value, Java.use("java.util.Map"));
    const entrySet = map.entrySet();

    // Cache the Map. Entry class once per call
    const MapEntry = Java.use("java.util.Map$Entry");

    return decodeIterable(entrySet, param, (entry) => {
      const typedEntry = entry!.getKey ? entry! : Java.cast(entry!, MapEntry);

      const key = typedEntry.getKey();
      const value = typedEntry.getValue();

      const keyType = key == null ? "java.lang.Object" : (key.$className ?? "java.lang.Object");
      const valueType = value == null ? "java.lang.Object" : (value.$className ?? "java.lang.Object");

      return {
        type: "java.util.Map.Entry",
        value: [
          { ...JavaDecoder.decode(key, { type: keyType, decoderSettings: param.decoderSettings }), name: "key" },
          { ...JavaDecoder.decode(value, { type: valueType, decoderSettings: param.decoderSettings }), name: "value" },
        ],
      } as DecodedValue;
    });
  },
};
