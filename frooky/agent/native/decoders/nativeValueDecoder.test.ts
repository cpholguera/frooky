import { DEFAULT_DECODER_SETTINGS } from "../../shared/defaultValues";
import { NativeValueDecoder } from "./nativeValueDecoder";

// Helper: allocate a NativePointer with a 32-bit integer value
function ptr32(value: number): NativePointer {
  const buf = Memory.alloc(4);
  buf.writeS32(value);
  return buf;
}

// Helper: allocate a NativePointer with a 64-bit integer value
function ptr64(value: number | Int64 | UInt64): NativePointer {
  const buf = Memory.alloc(8);
  buf.writeS64(value);
  return buf;
}

describe("NativeValueDecoder", () => {
  describe("decode()", () => {
    it("should decode void as null", () => {
      const decoder = new NativeValueDecoder("void", DEFAULT_DECODER_SETTINGS);
      expect(decoder.decode(ptr(0))).toEqual({ type: "void", value: null });
    });

    it("should decode bool true", () => {
      const decoder = new NativeValueDecoder("bool", DEFAULT_DECODER_SETTINGS);
      expect(decoder.decode(ptr(1))).toEqual({ type: "bool", value: true });
    });

    it("should decode bool false", () => {
      const decoder = new NativeValueDecoder("bool", DEFAULT_DECODER_SETTINGS);
      expect(decoder.decode(ptr(0))).toEqual({ type: "bool", value: false });
    });

    it("should decode char positive", () => {
      const decoder = new NativeValueDecoder("char", DEFAULT_DECODER_SETTINGS);
      expect(decoder.decode(ptr(65))).toEqual({ type: "char", value: 65 });
    });

    it("should decode char negative (sign extension)", () => {
      const decoder = new NativeValueDecoder("char", DEFAULT_DECODER_SETTINGS);
      expect(decoder.decode(ptr(0xff))).toEqual({ type: "char", value: -1 });
    });

    it("should decode int8 positive", () => {
      const decoder = new NativeValueDecoder("int8", DEFAULT_DECODER_SETTINGS);
      expect(decoder.decode(ptr(127))).toEqual({ type: "int8", value: 127 });
    });

    it("should decode int8 negative", () => {
      const decoder = new NativeValueDecoder("int8", DEFAULT_DECODER_SETTINGS);
      expect(decoder.decode(ptr(0x80))).toEqual({ type: "int8", value: -128 });
    });

    it("should decode uchar", () => {
      const decoder = new NativeValueDecoder("uchar", DEFAULT_DECODER_SETTINGS);
      expect(decoder.decode(ptr(0xff))).toEqual({ type: "uchar", value: 255 });
    });

    it("should decode uint8", () => {
      const decoder = new NativeValueDecoder("uint8", DEFAULT_DECODER_SETTINGS);
      expect(decoder.decode(ptr(0xff))).toEqual({ type: "uint8", value: 255 });
    });

    it("should decode int16 positive", () => {
      const decoder = new NativeValueDecoder("int16", DEFAULT_DECODER_SETTINGS);
      expect(decoder.decode(ptr(32767))).toEqual({ type: "int16", value: 32767 });
    });

    it("should decode int16 negative (sign extension)", () => {
      const decoder = new NativeValueDecoder("int16", DEFAULT_DECODER_SETTINGS);
      expect(decoder.decode(ptr(0x8000))).toEqual({ type: "int16", value: -32768 });
    });

    it("should decode uint16", () => {
      const decoder = new NativeValueDecoder("uint16", DEFAULT_DECODER_SETTINGS);
      expect(decoder.decode(ptr(0xffff))).toEqual({ type: "uint16", value: 65535 });
    });

    it("should decode int", () => {
      const decoder = new NativeValueDecoder("int", DEFAULT_DECODER_SETTINGS);
      expect(decoder.decode(ptr(42))).toEqual({ type: "int", value: 42 });
    });

    it("should decode int32", () => {
      const decoder = new NativeValueDecoder("int32", DEFAULT_DECODER_SETTINGS);
      expect(decoder.decode(ptr(1000))).toEqual({ type: "int32", value: 1000 });
    });

    it("should decode ssize_t", () => {
      const decoder = new NativeValueDecoder("ssize_t", DEFAULT_DECODER_SETTINGS);
      expect(decoder.decode(ptr(42))).toEqual({ type: "ssize_t", value: 42 });
    });

    it("should decode long", () => {
      const decoder = new NativeValueDecoder("long", DEFAULT_DECODER_SETTINGS);
      expect(decoder.decode(ptr(100))).toEqual({ type: "long", value: 100 });
    });

    it("should decode uint", () => {
      const decoder = new NativeValueDecoder("uint", DEFAULT_DECODER_SETTINGS);
      expect(decoder.decode(ptr(0xffff))).toEqual({ type: "uint", value: 65535 });
    });

    it("should decode uint32", () => {
      const decoder = new NativeValueDecoder("uint32", DEFAULT_DECODER_SETTINGS);
      expect(decoder.decode(ptr(1000))).toEqual({ type: "uint32", value: 1000 });
    });

    it("should decode size_t", () => {
      const decoder = new NativeValueDecoder("size_t", DEFAULT_DECODER_SETTINGS);
      expect(decoder.decode(ptr(1024))).toEqual({ type: "size_t", value: 1024 });
    });

    it("should decode ulong", () => {
      const decoder = new NativeValueDecoder("ulong", DEFAULT_DECODER_SETTINGS);
      expect(decoder.decode(ptr(999))).toEqual({ type: "ulong", value: 999 });
    });

    it("should decode int64", () => {
      const decoder = new NativeValueDecoder("int64", DEFAULT_DECODER_SETTINGS);
      const result = decoder.decode(ptr(12345));
      expect(result.type).toBe("int64");
      expect(result.value).toBe(int64(ptr(12345).toString()).valueOf());
    });

    it("should decode uint64", () => {
      const decoder = new NativeValueDecoder("uint64", DEFAULT_DECODER_SETTINGS);
      const result = decoder.decode(ptr(12345));
      expect(result.type).toBe("uint64");
      expect(result.value).toBe(uint64(ptr(12345).toString()).valueOf());
    });

    it("should decode float (raw int32 of pointer address)", () => {
      const decoder = new NativeValueDecoder("float", DEFAULT_DECODER_SETTINGS);
      expect(decoder.decode(ptr(42))).toEqual({ type: "float", value: 42 });
    });

    it("should decode double (raw int32 of pointer address)", () => {
      const decoder = new NativeValueDecoder("double", DEFAULT_DECODER_SETTINGS);
      expect(decoder.decode(ptr(42))).toEqual({ type: "double", value: 42 });
    });

    it("should cache the value decoder on second call", () => {
      const decoder = new NativeValueDecoder("int32", DEFAULT_DECODER_SETTINGS);
      decoder.decode(ptr(1));
      expect((decoder as any).cachedValueDecoder).not.toBeNull();
      expect(decoder.decode(ptr(99))).toEqual({ type: "int32", value: 99 });
    });
  });
});
