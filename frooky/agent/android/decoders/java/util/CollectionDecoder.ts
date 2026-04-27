// collectionDecoder.ts
import Java from "frida-java-bridge";
import type { BaseDecoder } from "../../../../shared/decoders/baseDecoder";
import type { JavaParam } from "../../../hook/javaParam";
import { decodeIterable } from "../lang/IterableDecoder";

export const CollectionDecoder: BaseDecoder<Java.Wrapper, JavaParam> = {
  decode: (value, param, settings) => {
    const iterable = value.iterator ? value : Java.cast(value, Java.use("java.util.Collection"));
    return decodeIterable(iterable, param, settings);
  },
};
