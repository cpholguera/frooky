import { DEFAULT_DECODER_SETTINGS } from "../defaultValues";
import { normalizeInputParam } from "./inputDecodableTypes";

describe("inputDecodableTypes", () => {
  describe("normalizeInputParam()", () => {
    it("should normalize a valid string to Param", () => {
      expect(normalizeInputParam("testParam")).toEqual({ type: "testParam", decodeAt: "enter", decoderSettings: DEFAULT_DECODER_SETTINGS });
    });
    it("should normalize [string, string] to a valid Param", () => {
      expect(normalizeInputParam(["testParam", "paramName"])).toEqual({
        type: "testParam",
        name: "paramName",
        decodeAt: "enter",
        decoderSettings: DEFAULT_DECODER_SETTINGS,
      });
    });
    it("should normalize a valid [string, InputParamSettings] to Param", () => {
      expect(
        normalizeInputParam(["testParam", { decodeAt: "exit", maxRecursion: 10, decodeLimit: 10, fastDecode: false, magicDecode: true }]),
      ).toEqual({
        type: "testParam",
        decodeAt: "exit",
        decoderSettings: {
          maxRecursion: 10,
          decodeLimit: 10,
          fastDecode: false,
          magicDecode: true,
        },
      });
    });
    it("should normalize to a valid [string, string, InputParamSettings] to Param", () => {
      expect(
        normalizeInputParam([
          "testParam",
          "paramName",
          { decodeAt: "exit", maxRecursion: 10, decodeLimit: 10, fastDecode: false, magicDecode: true },
        ]),
      ).toEqual({
        type: "testParam",
        name: "paramName",
        decodeAt: "exit",
        decoderSettings: {
          maxRecursion: 10,
          decodeLimit: 10,
          fastDecode: false,
          magicDecode: true,
        },
      });
    });
    it("should return Param unchanged", () => {
      expect(
        normalizeInputParam({
          type: "testParam",
          name: "paramName",
          decodeAt: "exit",
          decoderSettings: {
            maxRecursion: 10,
            decodeLimit: 10,
            fastDecode: false,
            magicDecode: true,
          },
        }),
      ).toEqual({
        type: "testParam",
        name: "paramName",
        decodeAt: "exit",
        decoderSettings: {
          maxRecursion: 10,
          decodeLimit: 10,
          fastDecode: false,
          magicDecode: true,
        },
      });
    });
  });
});
