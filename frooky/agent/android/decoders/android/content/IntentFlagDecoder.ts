import Java from "frida-java-bridge";
import { Decoder } from "../../../../shared/decoders/baseDecoder";
import { DecodedValue } from "../../../../shared/decoders/decodedValue";

export class IntentFlagDecoder extends Decoder<Java.Wrapper> {
  flags = this.loadIntentFlags();

  decode(value: Java.Wrapper): DecodedValue {
    const bitmask = Number(value) >>> 0;

    const decodedFlags: string[] = [];

    for (const { name, value: flag } of this.flags) {
      if (flag === 0) continue;
      if ((bitmask & flag) === flag) {
        decodedFlags.push(name);
      }
    }

    return {
      type: "android.content.IntentFlag",
      value: decodedFlags,
    };
  }
  loadIntentFlags() {
    const IntentClass = Java.use("android.content.Intent");
    const fields = IntentClass.class.getFields(); // public only
    const flags: Array<{ name: string; value: number }> = [];
    for (let i = 0; i < fields.length; i++) {
      const f = fields[i];
      const name: string = f.getName();
      if (!name.startsWith("FLAG_")) continue;
      if (f.getType().getName() !== "int") continue;
      flags.push({ name, value: f.getInt(null) >>> 0 });
    }
    return flags;
  }
}
