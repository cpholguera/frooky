import { validateAndRepairDecoderSettings, validateAndRepairFrookyConfig, validateAndRepairHookSettings, validateMetadata } from "./configValidator";
import { DEFAULT_DECODER_SETTINGS, DEFAULT_FROOKY_SETTINGS, DEFAULT_HOOK_SETTINGS } from "./defaultValues";
import { InputFrookyConfig } from "./frookyConfig";
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
        customDecoder: "",
        decoderArgs: [],
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

  describe("validateAndRepairFrookyConfig()", () => {
    const validFrookyConfig: InputFrookyConfig = {
      metadata: {
        name: "Test Config",
        platform: "Android",
      },
      settings: DEFAULT_FROOKY_SETTINGS,
      hookGroup: [],
    };
    it("should return a valid FrookyConfig for valid FrookyConfig", () => {
      expect(validateAndRepairFrookyConfig(validFrookyConfig, "Android")).toEqual(validFrookyConfig);
    });

    it("should return a valid FrookyConfig with default settings if no settings are passed", () => {
      const missingSettingsFrookyConfig: InputFrookyConfig = {
        metadata: {
          name: "Test Config",
          platform: "Android",
        },
        hookGroup: [],
      };
      expect(validateAndRepairFrookyConfig(missingSettingsFrookyConfig, "Android")).toEqual(validFrookyConfig);
    });

    it("should set the default setting values if only partially set", () => {
      const partialSettingsFrookyConfig: InputFrookyConfig = {
        metadata: {
          name: "Test Config",
          platform: "Android",
        },
        settings: {
          hookSettings: {
            stackTraceLimit: 55,
          },
          decoderSettings: {
            magicDecode: false,
          },
        },
        hookGroup: [],
      };
      const expectedFrookyConfig = partialSettingsFrookyConfig;
      expectedFrookyConfig.settings = { ...DEFAULT_FROOKY_SETTINGS, ...partialSettingsFrookyConfig.settings };
      expectedFrookyConfig.settings!.hookSettings = { ...DEFAULT_HOOK_SETTINGS, ...partialSettingsFrookyConfig.settings!.hookSettings };
      expectedFrookyConfig.settings!.decoderSettings = { ...DEFAULT_DECODER_SETTINGS, ...partialSettingsFrookyConfig.settings!.decoderSettings };
      expect(validateAndRepairFrookyConfig(partialSettingsFrookyConfig, "Android")).toEqual(expectedFrookyConfig);
    });

    it("should set the default values if settings are not according to schema", () => {
      const invalidSettingsFrookyConfig: InputFrookyConfig = {
        metadata: {
          name: "Test Config",
          platform: "Android",
        },
        settings: {
          hookSettings: {
            stackTraceLimit: "10" as unknown as number,
          },
          decoderSettings: {
            fastDecode: 10 as unknown as boolean,
          },
        },
        hookGroup: [],
      };
      expect(validateAndRepairFrookyConfig(invalidSettingsFrookyConfig, "Android")).toEqual(validFrookyConfig);
    });

    it("should warn if there are unknown properties in the setting", () => {
      const invalidSettingsFrookyConfig = {
        myCustomSettings: {},
        metadata: {
          name: "Test Config",
          platform: "Android",
        },
        hookGroup: [],
      };
      expect(() => {
        validateAndRepairFrookyConfig(invalidSettingsFrookyConfig as InputFrookyConfig, "Android");
      }).toLogWarn("Frooky config contains unknown properties");
    });

    it("should warn in case of an OS mismatch", () => {
      expect(() => {
        validateAndRepairFrookyConfig(validFrookyConfig, "iOS");
      }).toLogWarn("The platform declared in the frooky configuration does not match the actual platform (iOS). Not all hooks may be valid.");
    });

    it("should throw an exception if no hookGroup is set", () => {
      expect(() => {
        validateAndRepairFrookyConfig({ metadata: { name: "Config w/o hookGroup" } } as InputFrookyConfig, "iOS");
      }).toThrow("Frooky config Config w/o hookGroup, as it has no 'hookGroup'.");
    });
  });
});
