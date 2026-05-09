import z from "zod";
import { DEFAULT_DECODER_SETTINGS, DEFAULT_FROOKY_SETTINGS, DEFAULT_HOOK_SETTINGS } from "./defaultValues";
import { FrookyConfig } from "./frookyConfig";
import type { FrookyMetadata, Platform } from "./frookyMetadata";
import { DecoderSettings, FrookySettings, HookSettings } from "./frookySettings";
import { InputDecoderSettings, InputFrookySettings, InputHookSettings } from "./inputParsing/inputSettings";
import { frookyMetadataSchema } from "./inputParsing/zodSchemas/frookyMetadata.zod";
import { frookySettingsSchema } from "./inputParsing/zodSchemas/frookySettings.zod";
import { inputDecoderSettingsSchema, inputHookSettingsSchema } from "./inputParsing/zodSchemas/inputSettings.zod";

// validates the config settings
export function validateAndRepairFrookySettings(settings: InputFrookySettings): FrookySettings {
  frooky.log.info(`Validating frooky config settings`);
  const validatedSettings = DEFAULT_FROOKY_SETTINGS;

  if (settings.hookSettings) {
    validatedSettings.hookSettings = validateAndRepairHookSettings(settings.hookSettings);
  }

  if (settings.decoderSettings) {
    validatedSettings.decoderSettings = validateAndRepairDecoderSettings(settings.decoderSettings);
  }

  const result = frookySettingsSchema.safeParse(validatedSettings);

  if (!result.success) {
    for (const issue of result.error.issues) {
      const key = issue.path[0] as keyof FrookySettings;
      (settings as Record<keyof FrookySettings, unknown>)[key] = DEFAULT_FROOKY_SETTINGS[key];
      frooky.log.warn([
        `Frooky setting "'${key}'" contains invalid data:`,
        z.prettifyError(result.error),
        `The value for '${key}' was reset to the default: ${DEFAULT_FROOKY_SETTINGS[key]}`,
      ]);
    }
  }
  frooky.log.info(`Frooky config is valid`);
  return { ...DEFAULT_FROOKY_SETTINGS, ...validatedSettings };
}

// validates hook settings and replaces invalid settings with valid default values
// empty ones are set to the default
export function validateAndRepairHookSettings(settings: InputHookSettings): HookSettings {
  frooky.log.info(`Validating frooky hook settings`);
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
  frooky.log.info(`frooky hook settings are valid`);
  return { ...DEFAULT_HOOK_SETTINGS, ...settings };
}

// validates decoder settings and replaces invalid settings with valid default values
// empty ones are set to the default
export function validateAndRepairDecoderSettings(settings: InputDecoderSettings): DecoderSettings {
  frooky.log.info(`Validating frooky decoder settings`);
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
  frooky.log.info(`frooky decoder settings are valid`);
  return { ...DEFAULT_DECODER_SETTINGS, ...settings };
}

export function validateMetadata(metadata: FrookyMetadata, platform: Platform) {
  frooky.log.info(`Validating frooky metadata`);
  if (metadata.platform?.toLowerCase() !== platform.toLocaleLowerCase()) {
    frooky.log.warn(
      `The platform declared in the frooky configuration does not match the actual platform (${platform}). Not all hooks may be valid.`,
    );
  }
  const result = frookyMetadataSchema.safeParse(metadata);
  if (!result.success) {
    frooky.log.warn(`The metadata contains invalid entries: ${result.error}`);
  }
  frooky.log.info(`frooky meta data are valid`);
}

export function validateConfig(inputFrookyConfig: FrookyConfig, platform: Platform): FrookySettings {
  if (inputFrookyConfig.metadata) {
    frooky.log.info(`Metadata are valid.`);
    validateMetadata(inputFrookyConfig.metadata, platform);
    frooky.log.debug(`Metadata: ${JSON.stringify(inputFrookyConfig.metadata, null, 2)}`);
  } else {
    frooky.log.warn(`No metadata declared.`);
  }
  let settings: FrookySettings = DEFAULT_FROOKY_SETTINGS;
  if (inputFrookyConfig.settings) {
    settings = validateAndRepairFrookySettings(inputFrookyConfig.settings);
  }
  return settings;
}
