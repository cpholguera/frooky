import { JavaHookScope } from "./frookyConfigParsing/javaHookScope";
import { NativeHookScope } from "./frookyConfigParsing/nativeHookScope";
import { InputDecoderSettings, InputHookSettings } from "./frookyConfigParsing/settingsInput";
import { FrookyMetadata } from "./frookyMetadata";

/**
 * frooky configuration.
 */
export interface FrookyConfig {
  /**
   * Metadata about the hook collection
   */
  metadata?: FrookyMetadata;

  /**
   * Settings applied to all hooks in this frooky config
   */
  globalSettings?: {
    hookSettings?: InputHookSettings;
    decoderSettings?: InputDecoderSettings;
  };

  /**
   * Collection of hooks.
   */
  hookScopes: JavaHookScope[] | NativeHookScope[];
}
