import type { JavaHook } from './javaHook';
import type { NativeHook } from './nativeHook';
import type { ObjCHook } from './objcHook';

/**
 * Base hook configuration.
 *
 * @public
 */
export interface BaseHook {
  /**
   * Maximum number of stack frames to capture.
   */
  stackTraceLimit?: number;

  /**
   * Stack trace filters to apply.
   */
  eventFilter?: string[];
}


/**
 * frooky hook.
 */
export type Hook = JavaHook | ObjCHook | NativeHook

