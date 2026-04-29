import type { FrookyConfig, HookSettings, Platform } from "frooky";
import z from "zod";
import { DEFAULT_DECODER_SETTINGS, DEFAULT_HOOK_SETTINGS } from "../config";
import type { DecoderSettings } from "../decoders/decoderSettings";
import { type HookValidatorResult, validateHooks } from "./hookValidator";
import { hookMetadataSchema } from "../hookFileParsing/zodSchemas/frookyConfig.zod";
import { hookSettingsInputSchema, decoderSettingsInputSchema } from "../hookFileParsing/zodSchemas/settingsInput.zod";

export function validateAndNormalizeHookSettings(settings: HookSettings): HookSettings {
  const result = hookSettingsInputSchema.safeParse(settings);

  if (!result.success) {
    for (const issue of result.error.issues) {
      const key = issue.path[0] as keyof HookSettings;
      (settings as Record<keyof HookSettings, unknown>)[key] = DEFAULT_HOOK_SETTINGS[key];
      frooky.log.warn([`Hook setting "'${key}'" contains invalid data:`, z.prettifyError(result.error), `The value for '${key}' was reset to the default: ${DEFAULT_HOOK_SETTINGS[key]}`]);
    }
  }
  return settings;
}


export function validateAndNormalizeDecoderSettings(settings: DecoderSettings): DecoderSettings {
  const result = decoderSettingsInputSchema.safeParse(settings);

  if (!result.success) {
    for (const issue of result.error.issues) {
      const key = issue.path[0] as keyof DecoderSettings;
      (settings as Record<keyof DecoderSettings, unknown>)[key] = DEFAULT_DECODER_SETTINGS[key];
      frooky.log.warn([
        `Decoder setting "'${String(key)}'" contains invalid data:`,
        z.prettifyError(result.error),
        `The value for '${String(key)}' was reset to the default: ${String(DEFAULT_DECODER_SETTINGS[key])}`,
      ]);
    }
  }
  return settings;
}

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

  // validate global hook settings and set to default it not set
  if (frookyConfig.globalSettings?.hookSettings) {
    frookyConfig.globalSettings.hookSettings = validateAndNormalizeHookSettings(frookyConfig.globalSettings.hookSettings);
  }
  // validate global decoder settings and set to default it not set
  if (frookyConfig.globalSettings?.decoderSettings) {
    frookyConfig.globalSettings.decoderSettings = validateAndNormalizeDecoderSettings(frookyConfig.globalSettings.decoderSettings);
  }

  // validate hooks
  let hookValidatorResult: HookValidatorResult;
  if (frookyConfig.hooks) {
    hookValidatorResult = validateHooks(frookyConfig.hooks, platform, frookyConfig.globalSettings?.hookSettings, frookyConfig.globalSettings?.decoderSettings);

    frooky.log.info("Hook configuration successfully validated.");
    return hookValidatorResult;
  } else {
    throw Error("Config file does not have any hooks declared.");
  }
}
