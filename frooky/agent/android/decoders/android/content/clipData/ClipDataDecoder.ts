import Java from "frida-java-bridge";
import { Decoder } from "../../../../../shared/decoders/baseDecoder";
import { DecodedValue } from "../../../../../shared/decoders/decodedValue";

export class ClipDataDecoder extends Decoder<Java.Wrapper> {
  decode(value: Java.Wrapper): DecodedValue {
    const items: DecodedValue[] = [];

    const itemCount: number = value.getItemCount().valueOf();

    for (let i = 0; i < itemCount; i++) {
      const item = value.getItemAt(i);

      const clipDataItemDecoder = new ClipDataDecoder({
        type: "android.content.ClipData.Item",
        settings: this.decodable.settings,
      });

      items.push({
        type: "android.content.ClipData.Item",
        value: clipDataItemDecoder.decode(item),
      });
    }

    return {
      type: "android.content.ClipData",
      value: {
        description: value.getDescription(),
        itemCount: itemCount,
        items: items,
      },
    };
  }
}
