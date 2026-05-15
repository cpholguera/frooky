import z from "zod";
import { Platform } from "../shared/frookyMetadata";
import { DEFAULT_DECODER_SETTINGS, DEFAULT_FROOKY_SETTINGS, DEFAULT_HOOK_SETTINGS } from "./defaultValues";
import { InputFrookyConfig } from "./frookyConfig";
import { FrookyMetadata } from "./frookyMetadata";
import { DecoderSettings, FrookySettings, HookSettings } from "./frookySettings";
import { InputDecoderSettings, InputFrookySettings, InputHookSettings } from "./inputParsing/inputSettings";
import { frookyMetadataSchema } from "./inputParsing/zodSchemas/frookyMetadata.zod";
import { inputDecoderSettingsSchema, inputHookSettingsSchema } from "./inputParsing/zodSchemas/inputSettings.zod";

// validates the settings of a frooky config
export function validateAndRepairFrookyConfig(frookyConfig: InputFrookyConfig, platform: Platform): InputFrookyConfig {
  frooky.log.debug(`Validating frooky config`);

  if (frookyConfig.metadata) {
    validateMetadata(frookyConfig.metadata, platform);
  }

  if (!frookyConfig.hookGroup) {
    throw Error(`Frooky config ${frookyConfig.metadata?.name ? frookyConfig.metadata?.name : ""}, as it has no 'hookGroup'.`);
  }

  // warn, if the hook config contains unknown entries
  const knownKeys: (keyof InputFrookyConfig)[] = ["metadata", "settings", "hookGroup"];
  const extraKeys = Object.keys(frookyConfig).filter((k) => !knownKeys.includes(k as keyof InputFrookyConfig));
  if (extraKeys.length > 0) {
    frooky.log.warn(`Frooky config contains unknown properties: ${extraKeys.join(", ")}`);
  }

  if (!frookyConfig.settings) {
    frookyConfig.settings = DEFAULT_FROOKY_SETTINGS;
    return frookyConfig;
  } else {
    // validate and repair settings
    if (frookyConfig.settings) {
      frookyConfig.settings = validateAndRepairFrookySettings(frookyConfig.settings);
    }
    frooky.log.debug(`Frooky config is valid`);
    return frookyConfig;
  }
}

export function validateAndRepairFrookySettings(inputSettings: InputFrookySettings): FrookySettings {
  frooky.log.debug(`Validating frooky settings`);
  const validFrookySettings: FrookySettings = DEFAULT_FROOKY_SETTINGS;

  // validate and repair hook settings
  if (inputSettings.hookSettings) {
    validFrookySettings.hookSettings = validateAndRepairHookSettings(inputSettings.hookSettings);
  }

  // validate and repair decoder settings
  if (inputSettings.decoderSettings) {
    validFrookySettings.decoderSettings = validateAndRepairDecoderSettings(inputSettings.decoderSettings);
  }

  frooky.log.debug(`Frooky settings are valid`);
  return validFrookySettings;
}

// validates hook settings and replaces invalid settings with valid default values
// empty ones are set to the default
export function validateAndRepairHookSettings(settings: InputHookSettings): HookSettings {
  frooky.log.debug(`Validating frooky hook settings`);
  const result = inputHookSettingsSchema.safeParse(settings);

  if (!result.success) {
    for (const issue of result.error.issues) {
      const key = issue.path[0] as keyof HookSettings;
      (settings as Record<keyof HookSettings, unknown>)[key] = DEFAULT_HOOK_SETTINGS[key];
      frooky.log.warn([
        `Hook setting "'${key}'" contains invalid data:`,
        z.prettifyError(result.error),
        `The value for '${key}' was reset to the default: ${DEFAULT_HOOK_SETTINGS[key]}`,
      ]);
    }
  }

  const knownKeys = Object.keys(DEFAULT_HOOK_SETTINGS);
  const extraKeys = Object.keys(settings).filter((k) => !knownKeys.includes(k));
  if (extraKeys.length > 0) {
    frooky.log.warn(`Hook settings contain unknown properties: ${extraKeys.join(", ")}`);
  }

  frooky.log.debug(`frooky hook settings are valid`);
  return { ...DEFAULT_HOOK_SETTINGS, ...settings };
}

// validates decoder settings and replaces invalid settings with valid default values
// empty ones are set to the default
export function validateAndRepairDecoderSettings(settings: InputDecoderSettings): DecoderSettings {
  frooky.log.debug(`Validating frooky decoder settings`);
  const result = inputDecoderSettingsSchema.safeParse(settings);

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

  const knownKeys = Object.keys(DEFAULT_DECODER_SETTINGS);
  const extraKeys = Object.keys(settings).filter((k) => !knownKeys.includes(k));
  if (extraKeys.length > 0) {
    frooky.log.warn(`Decoder settings contain unknown properties: ${extraKeys.join(", ")}`);
  }

  frooky.log.debug(`frooky decoder settings are valid`);
  return { ...DEFAULT_DECODER_SETTINGS, ...settings };
}

export function validateMetadata(metadata: FrookyMetadata, platform: Platform) {
  frooky.log.debug(`Validating frooky metadata`);
  if (metadata.platform?.toLowerCase() !== platform.toLocaleLowerCase()) {
    frooky.log.warn(
      `The platform declared in the frooky configuration does not match the actual platform (${platform}). Not all hooks may be valid.`,
    );
  }
  const result = frookyMetadataSchema.safeParse(metadata);
  if (!result.success) {
    const pretty = z.prettifyError(result.error);
    frooky.log.warn(`The metadata contains invalid entries: ${pretty}`);
  }
  frooky.log.debug(`frooky meta data are valid`);
}
