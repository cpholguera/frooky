import { validateAndRepairHookSettings, validateMetadata } from "./configValidator";
import { DEFAULT_HOOK_SETTINGS } from "./defaultValues";
import { FrookyMetadata } from "./frookyMetadata";
import { InputHookSettings } from "./inputParsing/inputSettings";

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
      const incompleteInputHookSettings: InputHookSettings = {
        stackTraceLimit: "incorrect" as unknown as number,
        eventFilter: ["a", "b"],
      };
      expect(validateAndRepairHookSettings(incompleteInputHookSettings)).toEqual({
        stackTraceLimit: DEFAULT_HOOK_SETTINGS.stackTraceLimit,
        eventFilter: ["a", "b"],
      });
    });
  });
});
