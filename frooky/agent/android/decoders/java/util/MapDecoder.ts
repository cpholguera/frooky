import Java from "frida-java-bridge";
import type { DecodedValue, Decoder } from "../../../../shared/decoders/decoder";
import type { JavaParam } from "../../../hook/javaParameter";
import { lookupJavaDecoder } from "../../javaDecoderLookup";
import { decodeIterable } from "../lang/IterableDecoder";

export const MapDecoder: Decoder<Java.Wrapper, JavaParam> = {
  decode: (input, param) => {
    const map = input.entrySet ? input : Java.cast(input, Java.use("java.util.Map"));
    const entrySet = map.entrySet();

    // Cache the Map.Entry class once per call
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
          { ...lookupJavaDecoder(key, { type: keyType }).decode(key, { type: keyType }), name: "key" },
          { ...lookupJavaDecoder(value, { type: valueType }).decode(value, { type: valueType }), name: "value" },
        ],
      } as DecodedValue;
    });
  },
};
