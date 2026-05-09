import { FrookyMetadata, InputFrookySettings, InputJavaHookGroup, InputNativeHookGroup } from "frooky/shared";

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
  settings?: InputFrookySettings;

  /**
   * Collection of hooks.
   */
  hookGroup: InputJavaHookGroup[] | InputNativeHookGroup[];
}
