import type Java from "frida-java-bridge";
import type { DecodedValue, Decoder } from "../../shared/decoders/decoder";
import type { Param } from "../../shared/hook/parameter";
import { CollectionDecoder } from "./java/util/CollectionDecoder";
import { MapDecoder } from "./java/util/MapDecoder";

/*
 * This is the registry for complex java decoders.
 */
const registry: Record<string, Decoder> = {
  "java.util.Set": CollectionDecoder,
  "java.util.List": CollectionDecoder,
  "java.util.Map": MapDecoder,
};

const FallbackJavaDecoder: Decoder = {
  decode: (input: Java.Wrapper, param: Param): DecodedValue => {
    return {
      type: param.type,
      name: param.name,
      value: input.toString(),
    };
  },
};

export function getJavaInstanceDecoder(type: string): Decoder {
  return registry[type] ?? FallbackJavaDecoder;
}
