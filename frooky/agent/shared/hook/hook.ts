import type { BaseDecoder } from "../decoders/baseDecoder";
import type { DecoderSettings, ReturnDecoderSettings } from "../decoders/decoderSettings";
import type { ParamType } from "./param";

export interface FrookyReturnType {
  type: ParamType;
  decoder?: BaseDecoder<any, any>;
  decoderSettings: ReturnDecoderSettings;
}

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
 * Name of a Java or Objective-C method.
 *
 * @public
 */
export type MethodName = string;

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
