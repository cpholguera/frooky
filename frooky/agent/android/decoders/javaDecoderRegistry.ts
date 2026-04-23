import Java from "frida-java-bridge";
import { Decoder } from "../../shared/decoders/decoder";
import { IntentFlagDecoder } from "./android/content/IntentFlagDecoder";
import { KeyGenParameterSpecDecoder } from "./android/security/keystore/KeyGenParameterSpecDecoder";
import { CollectionDecoder } from "./java/util/CollectionDecoder";
import { MapDecoder } from "./java/util/MapDecoder";
import { JavaArrayDecoder } from "./javaArrayDecoder";
import { JavaLongDecoder } from "./javaDecoder";

/*
 * This is the registry for complex java decoders.
 */
export const javaDecoderRegistry: Record<string, Decoder<Java.Wrapper>> = {
  // special java decoders
  "JavaArrayDecoder": JavaArrayDecoder,
  "JavaLongDecoder": JavaLongDecoder,

  // java instances decoders
  "java.util.LinkedHashSet": CollectionDecoder,
  "java.util.Arrays$ArrayList": CollectionDecoder,
  "java.util.Collections$SingletonMap": MapDecoder,
  "android.security.keystore.KeyGenParameterSpec": KeyGenParameterSpecDecoder,

  // built it custom decoders
  "android.content.IntentFlagDecoder": IntentFlagDecoder,
};
