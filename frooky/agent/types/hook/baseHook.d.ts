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


