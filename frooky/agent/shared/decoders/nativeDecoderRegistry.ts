import { Decoder } from "./decoder";

/*
 * This is the registry for complex java decoders.
 */
export const nativeDecoderRegistry: Record<string, Decoder<NativePointer>> = {
  // // special native decoders
  // "JavaArrayDecoder": JavaArrayDecoder,
  // "JavaLongDecoder": JavaLongDecoder,

  // // java instances decoders
  // "java.util.LinkedHashSet": CollectionDecoder,
  // "java.util.Arrays$ArrayList": CollectionDecoder,
  // "java.util.Collections$SingletonMap": MapDecoder,
  // "android.security.keystore.KeyGenParameterSpec": KeyGenParameterSpecDecoder,

  // built it custom decoders
};
