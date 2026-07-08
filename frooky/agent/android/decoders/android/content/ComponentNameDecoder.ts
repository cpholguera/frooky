import Java from "frida-java-bridge";
import { Decoder } from "../../../../shared/decoders/baseDecoder";
import { DecodedValue } from "../../../../shared/decoders/decodedValue";

export class ComponentNameDecoder extends Decoder<Java.Wrapper> {
  decode(value: Java.Wrapper): DecodedValue {
    return {
      type: "android.content.ComponentName",
      value: {
        className: value.getClassName(),
        packageName: value.getPackageName(),
      },
    };
  }
}
