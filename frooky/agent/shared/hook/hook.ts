import type { HookMetadata } from "shared/frookyConfig";

/**
 * Frida-compatible type for a return value used with Native and Objective-C hooks
 *
 * @example "(NSString *)"
 * @example "int"
 * 
 * @public
 */
export type ReturnType = string;


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
   * Optional metadata for this hook. If provided, these values will be merged with the metadata defined in the frooky configuration during hook loading, and will take priority on conflict.
   *
   * @example The `description` field in the frooky config will be overwritten if this metadata also defines one.
   */
  metadata?: HookMetadata;

  /**
   * Maximum number of stack frames to capture.
   */
  stackTraceLimit?: number;

  /**
   * Stack trace filters to apply.
   */
  eventFilter?: string[];
}


