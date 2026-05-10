import {
  validateAndRepairDecoderSettings,
  validateAndRepairFrookySettings,
  validateAndRepairHookSettings,
  validateMetadata,
} from "./configValidator";
import { DEFAULT_DECODER_SETTINGS, DEFAULT_FROOKY_SETTINGS, DEFAULT_HOOK_SETTINGS } from "./defaultValues";
import { FrookyMetadata } from "./frookyMetadata";
import { InputDecoderSettings, InputFrookySettings, InputHookSettings } from "./inputParsing/inputSettings";
import { LogLevel } from "./logger";

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
      const invalidInputHookSettings = {
        stackTraceLumit: 10,
      };
      expect(() => {
        validateAndRepairHookSettings(invalidInputHookSettings as InputHookSettings);
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

  describe("validateAndRepairFrookySettings()", () => {
    it("should return a valid FrookySettings for valid InputDecoderSettings", () => {
      expect(validateAndRepairFrookySettings(DEFAULT_FROOKY_SETTINGS)).toEqual(DEFAULT_FROOKY_SETTINGS);
    });

    it("should set the default value if not set", () => {
      const targetFrookySettings = DEFAULT_FROOKY_SETTINGS;
      targetFrookySettings.verbose = true;
      targetFrookySettings.hookSettings.stackTraceLimit = 55;
      targetFrookySettings.decoderSettings.magicDecode = false;
      const incompleteInputFrookySettings: InputFrookySettings = {
        verbose: true,
        hookSettings: {
          stackTraceLimit: 55,
        },
        decoderSettings: {
          magicDecode: false,
        },
      };
      expect(validateAndRepairFrookySettings(incompleteInputFrookySettings)).toEqual(targetFrookySettings);
    });

    it("should set the default value if value is not according to schema", () => {
      const invalidInputFrookySettings: InputFrookySettings = {
        logLevel: false as unknown as LogLevel,
        hookSettings: {
          stackTraceLimit: "10" as unknown as number,
        },
        decoderSettings: {
          fastDecode: 10 as unknown as boolean,
        },
      };
      expect(validateAndRepairFrookySettings(invalidInputFrookySettings)).toEqual(DEFAULT_FROOKY_SETTINGS);
    });

    it("should warn if there are unknown properties in the setting", () => {
      const unknownInputFrookySettings = {
        someOtherSetting: false,
      };
      expect(() => {
        validateAndRepairFrookySettings(unknownInputFrookySettings as InputFrookySettings);
      }).toLogWarn("Frooky settings contain unknown properties");
    });
  });
});
