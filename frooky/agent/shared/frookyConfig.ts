import type { Hook, HookSettings } from "frooky";

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
   * Version of the hook collection.
   */
  version?: string | number;
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
  globalSettings?: HookSettings;

  /**
   * Collection of hooks.
   */
  hooks: Hook[];
}
