import { DEFAULT_DECODER_SETTINGS } from "../../shared/defaultValues";
import { NativeFallbackDecoder } from "./nativeFallbackDecoder";

describe("NativeFallbackDecoder", () => {
  describe("decode()", () => {
    it("should decode a unknown decodable to its address as string", () => {
      const decoder = new NativeFallbackDecoder({ type: "customStructType", settings: DEFAULT_DECODER_SETTINGS });
      expect(decoder.decode(ptr(0x12345678))).toEqual({ type: "customStructType", value: "0x12345678" });
    });

    it("should decode a unknown named decodable to its address as string", () => {
      const decoder = new NativeFallbackDecoder({ type: "customStructType", name: "customStructName", settings: DEFAULT_DECODER_SETTINGS });
      expect(decoder.decode(ptr(0x12345678))).toEqual({ type: "customStructType", name: "customStructName", value: "0x12345678" });
    });
  });
});
