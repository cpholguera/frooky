// collectionDecoder.ts
import Java from "frida-java-bridge";
import { decodeIterable, JavaParam } from "frooky/android";
import { BaseDecoder } from "frooky/shared";

export const CollectionDecoder: BaseDecoder<Java.Wrapper, JavaParam> = {
  decode: (value, param) => {
    const iterable = value.iterator ? value : Java.cast(value, Java.use("java.util.Collection"));
    return decodeIterable(iterable, param);
  },
};
