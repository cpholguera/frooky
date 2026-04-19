import type Java from "frida-java-bridge";
import { java_util_MapDecoder } from "../../build/decoders/java/util/MapDecoder";
import type { DecodedValue, Decoder } from "../../shared/decoders/decoder";
import type { Param } from "../../shared/hook/parameter";
import { android_content_IntentFlagDecoder } from "./android/content/IntentFlagDecoder";
import { android_security_keystore_KeyGenParameterSpecDecoder } from "./android/security/keytore/KeyGenParameterSpecDecoder";
import { java_util_CollectionDecoder } from "./java/util/CollectionDecoder";

/*
 * This is the registry for complex java decoders.
 */
const registry: Record<string, Decoder> = {
  // type decoders
  "java.util.LinkedHashSet": java_util_CollectionDecoder,
  "java.util.Arrays$ArrayList": java_util_CollectionDecoder,
  "java.util.Collections$SingletonMap": java_util_MapDecoder,
  "android.security.keystore.KeyGenParameterSpec": android_security_keystore_KeyGenParameterSpecDecoder,

  // built it custom decoders
  "android.content.IntentFlagDecoder": android_content_IntentFlagDecoder,
};

const FallbackJavaDecoder: Decoder = {
  decode: (input: Java.Wrapper, param: Param): DecodedValue => {
    return {
      type: param.implementationType ?? param.type,
      name: param.name,
      value: input.toString(),
    };
  },
};

export function getJavaInstanceDecoder(type: string): Decoder {
  return registry[type] ?? FallbackJavaDecoder;
}
