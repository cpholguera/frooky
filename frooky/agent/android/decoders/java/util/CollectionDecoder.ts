// collectionDecoder.ts
import Java from "frida-java-bridge";
import type { Decoder } from "../../../../shared/decoders/decoder";
import type { JavaParam } from "../../../hook/javaParameter";
import { decodeIterable } from "../lang/IterableDecoder";

export const CollectionDecoder: Decoder<Java.Wrapper, JavaParam> = {
  decode: (input, param) => {
    const iterable = input.iterator ? input : Java.cast(input, Java.use("java.util.Collection"));
    return decodeIterable(iterable, param);
  },
};
