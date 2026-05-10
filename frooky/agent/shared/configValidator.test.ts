import { validateAndRepairDecoderSettings, validateAndRepairHookSettings, validateMetadata } from "./configValidator";
import { DEFAULT_DECODER_SETTINGS, DEFAULT_HOOK_SETTINGS } from "./defaultValues";
import { FrookyMetadata } from "./frookyMetadata";
import { InputDecoderSettings, InputHookSettings } from "./inputParsing/inputSettings";

describe("configValidator", () => {
  describe("validateMetadata()", () => {
    const metadata: FrookyMetadata = {
      platform: "Android",
      name: "Test",
      description: "Test description",
      category: "Test category",
      author: "frooky devs",
      version: "1.0",
    };
    it("should warn in case of an OS mismatch", () => {
      expect(() => {
        validateMetadata(metadata, "iOS");
      }).toLogWarn("The platform declared in the frooky configuration does not match the actual platform (iOS). Not all hooks may be valid.");
    });
    it("should warn if its not according to the schema", () => {
      expect(() => {
        metadata.category = true as unknown as string;
        metadata.platform = "Windows Phone" as any;
        validateMetadata(metadata, "Android");
      }).toLogWarn("The metadata contains invalid entries");
    });
  });

  describe("validateAndRepairHookSettings()", () => {
    it("should return a valid HookSettings for valid InputHookSettings", () => {
      expect(validateAndRepairHookSettings(DEFAULT_HOOK_SETTINGS)).toEqual(DEFAULT_HOOK_SETTINGS);
    });
    it("should set the default value if not set", () => {
      const incompleteInputHookSettings: InputHookSettings = {
        eventFilter: ["a", "b"],
      };
      expect(validateAndRepairHookSettings(incompleteInputHookSettings)).toEqual({
        stackTraceLimit: DEFAULT_HOOK_SETTINGS.stackTraceLimit,
        eventFilter: ["a", "b"],
      });
    });
    it("should set the default value if value is not according to schema", () => {
      const incorrectInputHookSettings: InputHookSettings = {
        stackTraceLimit: "incorrect" as unknown as number,
        eventFilter: ["a", "b"],
      };
      expect(validateAndRepairHookSettings(incorrectInputHookSettings)).toEqual({
        stackTraceLimit: DEFAULT_HOOK_SETTINGS.stackTraceLimit,
        eventFilter: ["a", "b"],
      });
    });
    it("should warn if there are unknown properties in the setting", () => {
      const unknownInputHookSettings = {
        stackTraceLumit: 10,
      };
      expect(() => {
        validateAndRepairHookSettings(unknownInputHookSettings as InputHookSettings);
      }).toLogWarn("Hook settings contain unknown properties");
    });
  });

  describe("validateAndRepairDecoderSettings()", () => {
    it("should return a valid DecoderSettings for valid InputDecoderSettings", () => {
      expect(validateAndRepairDecoderSettings(DEFAULT_DECODER_SETTINGS)).toEqual(DEFAULT_DECODER_SETTINGS);
    });
    it("should set the default value if not set", () => {
      const incompleteInputDecoderSettings: InputDecoderSettings = {
        decodeLimit: 30,
      };
      expect(validateAndRepairDecoderSettings(incompleteInputDecoderSettings)).toEqual({
        fastDecode: false,
        magicDecode: false,
        maxRecursion: 10,
        decodeLimit: 30,
      });
    });
    it("should set the default value if value is not according to schema", () => {
      const incompleteInputDecoderSettings: InputDecoderSettings = {
        decodeLimit: false as unknown as number,
      };
      expect(validateAndRepairDecoderSettings(incompleteInputDecoderSettings)).toEqual(DEFAULT_DECODER_SETTINGS);
    });
    it("should warn if there are unknown properties in the setting", () => {
      const unknownInputDecoderSettings = {
        someOtherSetting: false,
      };
      expect(() => {
        validateAndRepairDecoderSettings(unknownInputDecoderSettings as InputDecoderSettings);
      }).toLogWarn("Decoder settings contain unknown properties");
    });
  });
});
