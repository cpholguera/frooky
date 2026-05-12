import { Decoder } from "../../shared/decoders/baseDecoder";
import { DecodedValue } from "../../shared/decoders/decodedValue";
import { FridaFundamentalType } from "./nativeFridaType";

type FundamentalValueDecoder = (input: NativePointer) => null | number | boolean;

const valueDecoders: Record<FridaFundamentalType, FundamentalValueDecoder> = {
  void: () => null,
  bool: (input) => input.toInt32() !== 0,
  char: (input) => {
    const r = input.toInt32() & 0xff;
    return r & 0x80 ? r - 0x100 : r;
  },
  int8: (input) => {
    const r = input.toInt32() & 0xff;
    return r & 0x80 ? r - 0x100 : r;
  },
  uchar: (input) => input.toInt32() & 0xff,
  uint8: (input) => input.toInt32() & 0xff,
  int16: (input) => {
    const r = input.toInt32() & 0xffff;
    return r & 0x8000 ? r - 0x10000 : r;
  },
  uint16: (input) => input.toInt32() & 0xffff,
  int: (input) => input.toInt32(),
  int32: (input) => input.toInt32(),
  ssize_t: (input) => input.toInt32(),
  long: (input) => input.toInt32(),
  uint: (input) => input.toUInt32(),
  uint32: (input) => input.toUInt32(),
  size_t: (input) => input.toUInt32(),
  ulong: (input) => input.toUInt32(),
  int64: (input) => int64(input.toString()).valueOf(),
  uint64: (input) => uint64(input.toString()).valueOf(),
  float: (input) => input.toInt32(),
  double: (input) => input.toInt32(),
};

export class NativeValueDecoder extends Decoder<NativePointer> {
  cachedValueDecoder: FundamentalValueDecoder | null = null;

  public decode(value: NativePointer): DecodedValue {
    if (!this.cachedValueDecoder) {
      this.cachedValueDecoder = valueDecoders[this.type as FridaFundamentalType];
    }
    return {
      type: this.type,
      value: this.cachedValueDecoder(value),
    };
  }
}
