import type { JavaHook } from './hook/javaHook';
import type { NativeHook } from './hook/nativeHook';
import type { ObjCHook } from './hook/objcHook';

/**
 * Target platform for hooks.
 *
 * @public
 */
export type Platform = 'Android' | 'iOS';

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
 * Hook can either be for Java, Native or Objective-C
 */
export type Hook = JavaHook | NativeHook | ObjCHook;


/**
 * frooky configuration.
 */
export interface FrookyConfig {
  /**
   * Metadata about the hook collection
   */
  metadata?: HookMetadata;
  /**
   * Collection of hooks.
   */
  hooks: Hook[];
}

