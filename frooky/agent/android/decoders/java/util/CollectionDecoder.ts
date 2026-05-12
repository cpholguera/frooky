// collectionDecoder.ts
import Java from "frida-java-bridge";
import { Decoder } from "../../../../shared/decoders/baseDecoder";
import { DecodedValue } from "../../../../shared/decoders/decodedValue";
import { decodeIterable } from "../lang/IterableDecoder";

export class CollectionDecoder extends Decoder<Java.Wrapper> {
  decode(value: Java.Wrapper): DecodedValue {
    const iterable = value.iterator ? value : Java.cast(value, Java.use("java.util.Collection"));
    return decodeIterable(iterable);
  }
}
