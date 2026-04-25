import type { NativeParam } from "../hook/nativeParameter";
import type { BaseDecoder, DecodedValue } from "./baseDecoder";
import type { FundamentalType } from "./nativeDecoder";
import { NativeFallbackDecoder } from "./nativeFallbackDecoder";

const referenceDecoders: Record<FundamentalType, (input: NativePointer) => null | number | boolean | string> = {
  void: () => null,
  bool: (input) => input.readU8() !== 0,
  char: (input) => {    // TODO: May be replaced in the future by a better string decoder
    try {
      return input.readUtf8String()
    } catch (e){
      return input.readS8()
    }
  },      
  int8: (input) => input.readS8(),
  uchar: (input) => {    // TODO: May be replaced in the future by a better string decoder
    try {
      return input.readUtf8String()
    } catch (e){
      return input.readS8()
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

export const NativeReferenceDecoder: BaseDecoder<NativePointer, NativeParam> = {
  decode: (input: NativePointer, param: NativeParam): DecodedValue => {
    const pointeeType = param.nativeType?.pointee as FundamentalType;
    const referenceDecoder = referenceDecoders[pointeeType];
    if (referenceDecoder) {
      return {
        type: param.type,
        name: param.name,
        value: referenceDecoder(input),
      };
    } else {
      return NativeFallbackDecoder.decode(input, param);
    }
  },
};
