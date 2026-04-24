import type { NativeParam } from "../hook/nativeParameter";
import type { DecodedValue, Decoder } from "./baseDecoder";

function decodeChar(input: NativePointer): number {
  const raw = input.toInt32() & 0xff;
  // sign-extend if bit 7 is set
  return raw & 0x80 ? raw - 0x100 : raw;
}

function decodeInt16(input: NativePointer): number {
  const raw = input.toInt32() & 0xffff;
  // sign-extend if bit 15 is set
  return raw & 0x8000 ? raw - 0x10000 : raw;
}

export const NativeFundamentalDecoder: Decoder<NativePointer, NativeParam> = {
  decode: (input: NativePointer, param: NativeParam): DecodedValue => {
    let value: number | bigint | boolean | null;
    switch (param.nativeType?.type) {
      case "void":
        value = null;
        break;
      case "bool":
        value = input.toInt32() !== 0;
        break;
      case "char":
      case "int8":
        value = decodeChar(input);
        break;
      case "uchar":
      case "uint8":
        value = input.toInt32() & 0xff;
        break;
      case "int16":
        value = decodeInt16(input);
        break;
      case "uint16":
        value = input.toInt32() & 0xffff;
        break;
      case "int":
      case "int32":
      case "ssize_t":
      case "long":
        value = input.toInt32();
        break;
      case "uint":
      case "uint32":
      case "size_t":
      case "ulong":
        value = input.toUInt32();
        break;
      case "int64":
        value = int64(input.toString()).valueOf();
        break;
      case "uint64":
        value = uint64(input.toString()).valueOf();
        break;
      case "float":
      case "double":
        value = input.toInt32(); // placeholder — floats need special handling
        break;
      default:
        value = null;
        break;
    }

    return {
      type: param.type,
      name: param.name,
      value,
    };
  },
};
