import { Decoder, DecoderArgs } from "../../shared/decoders/baseDecoder";
import { DecodedValue } from "../../shared/decoders/decodedValue";
import { DecoderSettings } from "../../shared/frookySettings";
import { toHexAndAscii } from "../../shared/utils";
import { FridaFundamentalType, FridaReferenceType } from "./nativeFridaType";

type ReferenceDecoder = (input: NativePointer, args?: DecoderArgs<NativePointer>[]) => any;

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
  uchar: (input, args) => {
    // TODO: should be generalized to be usable by other reference decoders (char *, int8....)
    // for now, we assume, that the first argument is the length of the array as an int
    try {
      if (args && args[0]) {
        frooky.log.debug(`uchar * Decoder: One argument passed.`);
        var decodedArg = args[0].decoder.decode(args[0].arg);
        frooky.log.debug(`uchar * Decoder: Decoded argument: ${JSON.stringify(decodedArg, null, 2)}`);

        if (typeof decodedArg.value != "number") {
          frooky.log.warn(`Argument passed to uchar decoder is not a number.`);
        } else {
          if (decodedArg.value) {
            var rawBytes = input.readByteArray(decodedArg.value);
            frooky.log.debug(`uchar * Decoder: Successfully read ${decodedArg.value} bytes of uchar *`);
            if (rawBytes !== null) {
              var bytes = new Uint8Array(rawBytes);
              return toHexAndAscii(bytes);
            }
          }
        }
      }
      return input.readUtf8String();
    } catch (e) {
      frooky.log.warn(`Unable to decode uchar *: ${e}`);
      return null;
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

export class NativeReferenceDecoder extends Decoder<NativePointer> {
  protected fridaReference: FridaReferenceType;
  protected cachedDecoder: ReferenceDecoder | null = null;

  constructor(type: string, settings: DecoderSettings, fridaReference: FridaReferenceType) {
    super(type, settings);
    this.fridaReference = fridaReference;
  }

  public decode(value: NativePointer, args?: DecoderArgs<NativePointer>[]): DecodedValue {
    if (this.cachedDecoder === null) {
      this.cachedDecoder = referenceDecoders[this.fridaReference.pointee];
    }
    return {
      type: this.type,
      value: this.cachedDecoder(value, args),
    };
  }
}
