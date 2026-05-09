// collectionDecoder.ts
import Java from "frida-java-bridge";
import { BaseDecoder } from "../../../../shared";
import { JavaParam } from "../../../hook/javaParam";
import { decodeIterable } from "../lang/IterableDecoder";

export const CollectionDecoder: BaseDecoder<Java.Wrapper, JavaParam> = {
  decode: (value, param) => {
    const iterable = value.iterator ? value : Java.cast(value, Java.use("java.util.Collection"));
    return decodeIterable(iterable, param);
  },
};
