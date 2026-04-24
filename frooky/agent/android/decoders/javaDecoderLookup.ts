import type Java from "frida-java-bridge";
import type { Decoder } from "../../shared/decoders/decoder";
import type { JavaParam } from "../hook/javaParameter";
import { IntentFlagDecoder } from "./android/content/IntentFlagDecoder";
import { KeyGenParameterSpecDecoder } from "./android/security/keystore/KeyGenParameterSpecDecoder";
import { CollectionDecoder } from "./java/util/CollectionDecoder";
import { MapDecoder } from "./java/util/MapDecoder";
import { JavaArrayDecoder } from "./javaArrayDecoder";
import { FallbackJavaDecoder, JavaLongDecoder, PrimitiveDecoder } from "./javaBasicDecoder";

/*
 * This is the registry for complex java decoders.
 */
const javaDecoderRegistry: Record<string, Decoder<Java.Wrapper, JavaParam>> = {
  // special java decoders
  JavaArrayDecoder: JavaArrayDecoder,
  JavaLongDecoder: JavaLongDecoder,

  // java instances decoders
  "java.util.LinkedHashSet": CollectionDecoder,
  "java.util.Arrays$ArrayList": CollectionDecoder,
  "java.util.Collections$SingletonMap": MapDecoder,
  "android.security.keystore.KeyGenParameterSpec": KeyGenParameterSpecDecoder,

  // built it custom decoders
  "android.content.IntentFlagDecoder": IntentFlagDecoder,
};

/**
 * Resolve the concrete Decoder for `input` under `param`.
 * Called only on the first invocation for a given Param; the result is cached
 * on `param.decoder` so subsequent calls skip this dispatch entirely.
 */
export function lookupJavaDecoder(input: Java.Wrapper, param: JavaParam): Decoder<Java.Wrapper, JavaParam> {
  // return cached decoder immediately
  const cachedDecoder = param.decoder;
  if (cachedDecoder) {
    return cachedDecoder;
  }

  // java array decoder
  if (param.type.startsWith("[")) {
    return javaDecoderRegistry.JavaArrayDecoder;
  }

  // long decoder
  if (param.type === "long") {
    return javaDecoderRegistry.JavaLongDecoder;
  }

  // query the java decoder registry for decoder for the java types
  if (typeof input === "object") {
    // the implementation can be different from the declaration
    // this happens when the declaration is an interface
    // we store the actual implementation type of the object
    param.implementationType = input.$className;
    return javaDecoderRegistry[param.implementationType] ?? FallbackJavaDecoder;
  }

  // Primitive JS value (already converted by Frida)
  return PrimitiveDecoder;
}
