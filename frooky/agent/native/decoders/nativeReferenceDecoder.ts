import { Decoder } from "../../shared/decoders/baseDecoder";
import { DecodedValue } from "../../shared/decoders/decodedValue";
import { NativeReferenceDecodable } from "./nativeDecodable";
import { FridaFundamentalType } from "./nativeFridaType";

type ReferenceDecoder = (input: NativePointer) => null | number | boolean | string;

const referenceDecoders: Record<FridaFundamentalType, ReferenceDecoder> = {
  void: () => null,
  bool: (input) => input.readU8() !== 0,
  char: (input) => {
    // TODO: May be replaced in the future by a better string decoder
    try {
      return input.readUtf8String();
    } catch (e) {
      return input.readS8();
    }
  },
  int8: (input) => input.readS8(),
  uchar: (input) => {
    // TODO: May be replaced in the future by a better string decoder
    try {
      return input.readUtf8String();
    } catch (e) {
      return input.readS8();
    }
  },
  uint8: (input) => input.readU8(),
  int16: (input) => input.readS16(),
  uint16: (input) => input.readU16(),
  int: (input) => input.readS32(),
  int32: (input) => input.readS32(),
  ssize_t: (input) => input.readS32(),
  long: (input) => input.readS32(),
  uint: (input) => input.readU32(),
  uint32: (input) => input.readU32(),
  size_t: (input) => input.readU32(),
  ulong: (input) => input.readU32(),
  int64: (input) => input.readS64().valueOf(),
  uint64: (input) => input.readU64().valueOf(),
  float: (input) => input.readFloat(),
  double: (input) => input.readDouble(),
};

export class NativeReferenceDecoder extends Decoder<NativeReferenceDecodable, NativePointer> {
  cachedDecoder: ReferenceDecoder | null = null;

  public decode(value: NativePointer): DecodedValue {
    if (this.cachedDecoder === null) {
      this.cachedDecoder = referenceDecoders[this.kind.fridaType.pointee];
    }
    return {
      type: this.kind.type,
      value: this.cachedDecoder(value),
    };
  }
}
