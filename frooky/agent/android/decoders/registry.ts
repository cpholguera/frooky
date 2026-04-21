import type Java from "frida-java-bridge";
import type { DecodedValue, Decoder } from "../../shared/decoders/decoder";
import type { Param } from "../../shared/hook/parameter";
import { MapDecoder } from "../decoders/java/util/MapDecoder";
import { IntentFlagDecoder } from "./android/content/IntentFlagDecoder";
import { KeyGenParameterSpecDecoder } from "./android/security/keystore/KeyGenParameterSpecDecoder";
import { CollectionDecoder } from "./java/util/CollectionDecoder";

/*
 * This is the registry for complex java decoders.
 */
const registry: Record<string, Decoder<Java.Wrapper>> = {
  // type decoders
  "java.util.LinkedHashSet": CollectionDecoder,
  "java.util.Arrays$ArrayList": CollectionDecoder,
  "java.util.Collections$SingletonMap": MapDecoder,
  "android.security.keystore.KeyGenParameterSpec": KeyGenParameterSpecDecoder,

  // built it custom decoders
  "android.content.IntentFlagDecoder": IntentFlagDecoder,
};

const FallbackJavaDecoder: Decoder<Java.Wrapper> = {
  decode: (input: Java.Wrapper, param: Param): DecodedValue => {
    return {
      type: param.implementationType ?? param.type,
      name: param.name,
      value: input.toString(),
    };
  },
};

export function getJavaInstanceDecoder(type: string): Decoder<Java.Wrapper> {
  return registry[type] ?? FallbackJavaDecoder;
}
