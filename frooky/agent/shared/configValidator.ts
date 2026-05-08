import z from "zod";
import type { DecoderSettings } from "./decoders/decoderSettings";
import { DEFAULT_DECODER_SETTINGS, DEFAULT_HOOK_SETTINGS } from "./defaultValues";
import { FrookyConfig } from "./frookyConfig";
import type { FrookyMetadata, Platform } from "./frookyMetadata";
import { HookSettings } from "./hook/hookSettings";
import { InputDecoderSettings, InputHookSettings } from "./inputParsing/inputSettings";
import { frookyMetadataSchema } from "./inputParsing/zodSchemas/frookyMetadata.zod";
import { inputDecoderSettingsSchema, inputHookSettingsSchema } from "./inputParsing/zodSchemas/inputSettings.zod";

// validates hook settings and replaces invalid settings with valid default values
// empty ones are set to the default
export function validateAndRepairHookSettings(settings: InputHookSettings): HookSettings {
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
  return { ...DEFAULT_HOOK_SETTINGS, ...settings };
}

// validates decoder settings and replaces invalid settings with valid default values
// empty ones are set to the default
export function validateAndRepairDecoderSettings(settings: InputDecoderSettings): DecoderSettings {
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
  return { ...DEFAULT_DECODER_SETTINGS, ...settings };
}

export function validateMetadata(metadata: FrookyMetadata, platform: Platform) {
  if (metadata.platform?.toLowerCase() !== platform.toLocaleLowerCase()) {
    frooky.log.warn(
      `The platform declared in the frooky configuration does not match the actual platform (${platform}). Not all hooks may be valid.`,
    );
  }
  const result = frookyMetadataSchema.safeParse(metadata);
  if (!result.success) {
    frooky.log.warn(`The metadata contains invalid entries: ${result.error}`);
  }
}

export function validateConfig(
  inputFrookyConfig: FrookyConfig,
  platform: Platform,
): { globalHookSettings: HookSettings; globalDecoderSettings: DecoderSettings } {
  if (inputFrookyConfig.metadata) {
    frooky.log.info(`Metadata are valid.`);
    validateMetadata(inputFrookyConfig.metadata, platform);
    frooky.log.debug(`Metadata: ${JSON.stringify(inputFrookyConfig.metadata, null, 2)}`);
  } else {
    frooky.log.warn(`No metadata declared.`);
  }

  let globalHookSettings: HookSettings = DEFAULT_HOOK_SETTINGS;
  if (inputFrookyConfig.globalSettings?.hookSettings) {
    globalHookSettings = validateAndRepairHookSettings(inputFrookyConfig.globalSettings.hookSettings);
    frooky.log.info(`Global settings are valid.`);
    frooky.log.debug(`Global settings: ${JSON.stringify(inputFrookyConfig.globalSettings.hookSettings, null, 2)}`);
  }

  let globalDecoderSettings: DecoderSettings = DEFAULT_DECODER_SETTINGS;
  if (inputFrookyConfig.globalSettings?.decoderSettings) {
    globalDecoderSettings = validateAndRepairDecoderSettings(inputFrookyConfig.globalSettings.decoderSettings);
    frooky.log.info(`Global decoder settings are valid.`);
    frooky.log.debug(`Global decoder settings: ${JSON.stringify(inputFrookyConfig.globalSettings.decoderSettings, null, 2)}`);
  }

  return { globalHookSettings, globalDecoderSettings };
}
