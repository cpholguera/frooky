import { Decoder } from "../../shared/decoders/baseDecoder";
import { Decodable } from "../../shared/decoders/decodable";
import { DecodedValue } from "../../shared/decoders/decodedValue";
import { DecoderSettings } from "../../shared/frookySettings";
import { toHexAndAscii } from "../../shared/utils";
import { FridaFundamentalType, FridaReferenceType } from "./nativeFridaType";

type ReferenceDecoder = (input: NativePointer, setting: DecoderSettings, arg?: DecodedValue) => any;

const referenceDecoders: Record<FridaFundamentalType, ReferenceDecoder> = {
  void: (input, setting, arg) => {
    // TODO: should be generalized to be usable by other reference decoders (char *, int8....)
    // for now, we assume, that the first argument is the length of the array as an int
    try {
      if (arg) {
        if (typeof arg.value != "number") {
          throw Error(`void * Decoder: Argument must be a number, but it is: ${arg.value}`);
        }
        frooky.log.debug(`void * Decoder: Decoder argument passed: ${arg.value}`);

        let readLength: number;
        if (arg.value > setting.decodeLimit) {
          frooky.log.debug(`void * Decoder: Setting the argument value of ${arg.value} to the max decode length of ${setting.decodeLimit}.`);
          readLength = setting.decodeLimit;
        } else {
          readLength = arg.value;
        }
        const rawBytes = input.readByteArray(readLength);
        frooky.log.debug(`void * Decoder: Successfully read ${readLength} bytes`);
        if (rawBytes !== null) {
          var bytes = new Uint8Array(rawBytes);
          return toHexAndAscii(bytes);
        }
      }
    } catch (e) {
      frooky.log.warn(`Unable to decode void *: ${e}`);
      return null;
    }
  },
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
  uchar: (input, setting, arg) => {
    // TODO: should be generalized to be usable by other reference decoders (char *, int8....)
    // for now, we assume, that the first argument is the length of the array as an int
    try {
      if (arg) {
        if (typeof arg.value != "number") {
          throw Error(`Argument for uchar * decoder must be a number, but it is: ${arg.value}`);
        }
        // frooky.log.debug(`uchar * Decoder: Decoder argument passed: ${JSON.stringify(arg, null, 2)}.`);

        const decodeLength = arg.value > setting.decodeLimit ? setting.decodeLimit : arg.value;
        const rawBytes = input.readByteArray(decodeLength);
        frooky.log.debug(`uchar * Decoder: Successfully read ${arg} bytes of uchar *`);
        if (rawBytes !== null) {
          var bytes = new Uint8Array(rawBytes);
          return toHexAndAscii(bytes);
        }
      } else {
        try {
          return input.readUtf8String();
        } catch (e) {
          return input.readS8();
        }
      }
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

  constructor(decodable: Decodable, fridaReference: FridaReferenceType) {
    super(decodable);
    this.fridaReference = fridaReference;
  }

  public decode(value: NativePointer, arg?: DecodedValue): DecodedValue {
    if (this.cachedDecoder === null) {
      this.cachedDecoder = referenceDecoders[this.fridaReference.pointee];
    }
    return {
      type: this.decodable.type,
      name: this.decodable.name,
      value: this.cachedDecoder(value, this.decodable.settings, arg),
    };
  }
}
