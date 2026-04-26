import type { FrookyConfig, Platform } from "frooky";
import { hookMetadataSchema } from "../hookFileParsing/zodSchemas/frookyConfig.zod";
import { hookSettingsSchema } from "../hookFileParsing/zodSchemas/hook.zod";
import { type HookValidatorResult, validateHooks } from "./hookValidator";

export function validateFrookyConfig(frookyConfig: FrookyConfig, platform: Platform): HookValidatorResult {
  frooky.log.info(`Validating frooky configuration for platform ${platform}`);

  if (!frookyConfig) {
    throw Error("No or empty frooky configuration provided.");
  }

  // validate metadata
  if (frookyConfig.metadata) {
    frooky.log.info(`frooky config metadata:\n${JSON.stringify(frookyConfig.metadata, null, 2)}`);
    if (frookyConfig.metadata.platform?.toLowerCase() !== platform.toLocaleLowerCase()) {
      frooky.log.warn(`The platform declared in the frooky configuration does not match the actual platform (${platform}). Not all hooks may be valid.`);
    }
    try {
      hookMetadataSchema.parse(frookyConfig.metadata);
    } catch (e) {
      frooky.log.warn(`The metadata contains invalid entires: ${e}`);
    }
  } else {
    frooky.log.warn("This frooky configuration does not have metadata. Consider adding them for better results.");
  }

  // validate global settings
  if (frookyConfig.globalSetting) {
    try {
      hookSettingsSchema.parse(frookyConfig.globalSetting);
    } catch (e) {
      frooky.log.warn(`The global settings contains invalid entires: ${e}`);
    }
  }

  // validate hooks
  let hookValidatorResult: HookValidatorResult;
  if (frookyConfig.hooks) {
    hookValidatorResult = validateHooks(frookyConfig.hooks, platform, frookyConfig.globalSetting, frookyConfig.metadata);

    frooky.log.info("Hook configuration validated.");
    return hookValidatorResult;
  } else {
    throw Error("Config file does not have any hooks declared.");
  }
}
