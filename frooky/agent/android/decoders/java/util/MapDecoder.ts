import Java from "frida-java-bridge";
import type { DecodedValue, Decoder } from "../../../../shared/decoders/decoder";
import type { Param } from "../../../../shared/hook/parameter";
import { JavaDecoder } from "../../javaDecoder";
import { decodeIterable } from "../lang/IterableDecoder";

export const MapDecoder: Decoder = {
  decode: (input, param) => {
    const map = input.entrySet ? input : Java.cast(input, Java.use("java.util.Map"));
    const entrySet = map.entrySet();

    // Cache the Map.Entry class once per call - note the '$' (inner class)
    const MapEntry = Java.use("java.util.Map$Entry");

    return decodeIterable(entrySet, param, (entry) => {
      // Frida returns a generic wrapper; cast so getKey/getValue are exposed.
      const typedEntry = entry!.getKey ? entry! : Java.cast(entry!, MapEntry);

      const key = typedEntry.getKey();
      const value = typedEntry.getValue();

      const keyType = key == null ? "java.lang.Object" : (key.$className ?? "java.lang.Object");
      const valueType = value == null ? "java.lang.Object" : (value.$className ?? "java.lang.Object");

      return {
        type: "java.util.Map.Entry",
        value: [{ ...JavaDecoder.decode(key, { type: keyType } as Param), name: "key" } as DecodedValue, { ...JavaDecoder.decode(value, { type: valueType } as Param), name: "value" } as DecodedValue],
      } as DecodedValue;
    });
  },
};
