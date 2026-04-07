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


