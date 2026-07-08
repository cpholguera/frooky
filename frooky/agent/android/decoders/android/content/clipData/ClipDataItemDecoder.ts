import Java from "frida-java-bridge";
import { Decoder } from "../../../../../shared/decoders/baseDecoder";
import { DecodedValue } from "../../../../../shared/decoders/decodedValue";

export class ClipDataItemDecoder extends Decoder<Java.Wrapper> {
  decode(value: Java.Wrapper): DecodedValue {
    const htmlText = value.getHtmlText();
    const text = value.getText();
    const uri = value.getUri();
    return {
      type: "android.content.ClipData.Item",
      value: {
        htmlText: htmlText != null ? htmlText.toString() : null,
        text: text != null ? text.toString() : null,
        uri: uri != null ? uri.toString() : null,
      },
    };
  }
}
