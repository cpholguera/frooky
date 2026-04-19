// collectionDecoder.ts
import Java from "frida-java-bridge";
import type { Decoder } from "../../../../shared/decoders/decoder";
import { decodeIterable } from "../lang/IterableDecoder";

export const java_util_CollectionDecoder: Decoder = {
  decode: (input, param) => {
    const iterable = input.iterator ? input : Java.cast(input, Java.use("java.util.Collection"));
    return decodeIterable(iterable, param);
  },
};
