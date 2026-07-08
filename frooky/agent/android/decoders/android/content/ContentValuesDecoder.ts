import Java from "frida-java-bridge";
import { Decoder } from "../../../../shared/decoders/baseDecoder";
import { DecodedValue } from "../../../../shared/decoders/decodedValue";

export class ContentValuesDecoder extends Decoder<Java.Wrapper> {
  decode(value: Java.Wrapper): DecodedValue {
    const result: Record<string, unknown> = {};

    const keySet = value.keySet();
    const iterator = keySet.iterator();

    while (iterator.hasNext()) {
      const key = iterator.next().toString();
      const val = value.get(key);
      result[key] = val != null ? val.toString() : null;
    }

    return {
      type: "android.content.ContentValues",
      value: result,
    };
  }
}
