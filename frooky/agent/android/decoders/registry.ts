import type Java from "frida-java-bridge";
import type { DecodedValue, Decoder } from "../../shared/decoders/decoder";
import type { Param } from "../../shared/hook/parameter";
import { IteratorDecoder } from "./java/util/IteratorDecoder";

const registry: Record<string, Decoder> = {
  "java.util.Set": IteratorDecoder,
  "java.util.List": IteratorDecoder,
};

const fallbackDecoder: Decoder = {
  decode: (input: Java.Wrapper, param: Param): DecodedValue => {
    return {
      type: param.type,
      name: param.name,
      value: input.toString(),
    };
  },
};

export function getJavaInstanceDecoder(type: string): Decoder {
  return registry[type] ?? fallbackDecoder;
}
