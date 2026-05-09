import { FrookyMetadata } from "./frookyMetadata";
import { InputJavaHookGroup } from "./inputParsing/inputJavaHookGroup";
import { InputNativeHookGroup } from "./inputParsing/inputNativeHookGroup";
import { InputFrookySettings } from "./inputParsing/inputSettings";

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
