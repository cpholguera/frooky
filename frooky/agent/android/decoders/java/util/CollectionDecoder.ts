// collectionDecoder.ts
import Java from "frida-java-bridge";
import type { BaseDecoder } from "../../../../shared/decoders/baseDecoder";
import type { JavaParam } from "../../../hook/javaParam";
import { decodeIterable } from "../lang/IterableDecoder";

export const CollectionDecoder: BaseDecoder<Java.Wrapper, JavaParam> = {
  decode: (input, param) => {
    const iterable = input.iterator ? input : Java.cast(input, Java.use("java.util.Collection"));
    return decodeIterable(iterable, param);
  },
};
