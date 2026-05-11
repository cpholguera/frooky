// collectionDecoder.ts
import Java from "frida-java-bridge";
import { Decoder } from "../../../../shared/decoders/baseDecoder";
import { JavaParam } from "../../../hook/javaParam";
import { decodeIterable } from "../lang/IterableDecoder";

export const CollectionDecoder: Decoder<Java.Wrapper, JavaParam> = {
  decode: (value, param) => {
    const iterable = value.iterator ? value : Java.cast(value, Java.use("java.util.Collection"));
    return decodeIterable(iterable, param);
  },
};
