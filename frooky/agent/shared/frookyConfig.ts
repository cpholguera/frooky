import type { Hook } from "frooky";

/**
 * Target platform for hooks.
 *
 * @public
 */
export type Platform = "Android" | "iOS";

/**
 * Metadata that describes a hook collection.
 *
 * @public
 */
export interface HookMetadata {
  /**
   * Target platform for the hook collection.
   */
  platform?: Platform;

  /**
   * Name of the hook collection.
   */
  name?: string;

  /**
   * Short description of the hook collection.
   */
  description?: string;

  /**
   * Category of the hook collection. Can, for example, be used to filter or group events.
   */
  category?: string;

  /**
   * Author or organization that maintains the hook collection.
   */
  author?: string;

  /**
   * Semantic version of the hook collection.
   *
   * @example "1.0.0"
   */
  version?: string;
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
  stackTraceLimit?: number;

  /**
   * If set, disables the stack trace.
   */
  disableStacktrace?: boolean;

  /**
   * If set, the decoders are instructed to prioritize speed over details. Mostly, this mean avoiding expensive Frida <-> native roundtrips.
   */
  fastDecode?: boolean;

  /**
   * If set, frooky tries to guess the type of a value in case it is not declared in the hook, or it is not possible to deduct it at runtime.
   */
  magicDecode?: boolean;

  /**
   * Sets the cutoff limit for the recursion depth when decoding nested data structures, such as nested arrays, lists, sets, maps, structs etc.
   */
  decoderMaxRecursion?: number;

  /**
   * Sets the limit of how many elements of enumerable data structures, such as arrays, lists, dictionaries etc. are decoded.
   */
  decoderMaxElements?: number;

  /**
   * Stack trace filters to apply.
   */
  eventFilter?: [string];
}

/**
 * frooky configuration.
 */
export interface FrookyConfig {
  /**
   * Metadata about the hook collection
   */
  metadata?: HookMetadata;

  /**
   * Settings applied to all hooks in this frooky config
   */
  globalSetting?: HookSettings;

  /**
   * Collection of hooks.
   */
  hooks: Hook[];
}
