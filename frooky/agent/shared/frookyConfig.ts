import { FrookyMetadata as InputFrookyMetadata } from "./frookyMetadata";
import { InputJavaHookGroup } from "./inputParsing/inputJavaHookGroup";
import { InputNativeHookGroup } from "./inputParsing/inputNativeHookGroup";
import { InputFrookySettings } from "./inputParsing/inputSettings";

/**
 * frooky configuration.
 */
export interface InputFrookyConfig {
  /**
   * Metadata about the hook collection
   */
  metadata?: InputFrookyMetadata;

  /**
   * Settings applied to all hooks in this frooky config
   */
  settings?: InputFrookySettings;

  /**
   * Collection of hooks.
   */
  hookGroup: InputJavaHookGroup[] | InputNativeHookGroup[];
}
