import type { DecoderSettings } from "../decoders/decoderSettings";

/**
 * Metadata that describes a hook collection.
 *
 * @public
 */
export interface HookSettings {
  /**
   * Sets stackTraceLimit to the given value for all hooks.
   */
  stackTraceLimit: number;

  /**
   * Stack trace filters to apply.
   */
  eventFilter: string[];

  /**
   * Timeout in seconds frooky will try to hook in case something the target library is not available.
   */
  hookTimeout: number;
}

/**
 * Base hook configuration.
 *
 * @public
 */
export interface Hook {
  /**
   * Hook settings applied to all its hooks and their decoders
   */
  hookSettings: HookSettings;
  /**
   * Decoder settings applied to all its hooks and their decoders
   */
  decoderSettings: DecoderSettings;
}
