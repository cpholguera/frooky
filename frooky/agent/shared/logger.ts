/**
 * Controls whether log output is enabled.
 * Defaults to `false` — call {@link enableLogging} to activate.
 */
let enabled = false;

/**
 * Enables log output for {@link log}.
 * Typically called during app initialization when verbose mode is requested.
 */
export function enableLogging(): void {
    enabled = true;
}

/**
 * Simple logger for the frooky app.
 * Output is suppressed unless {@link enableLogging} has been called.
 * Errors are always logged regardless of the enabled state.
 *
 * @example
 * ```ts

* enableLogging();
* log.info(&quot;Initializing frooky&quot;);
* log.warn(&quot;Target not recognized&quot;);
* log.error(&quot;Agent failed to start&quot;);
* ```
 */
export const log = {
    /**
     * Logs an informational message.
     * @param msg - The message to log.
     */
    info: (msg: string): void => { if (enabled) console.log(`[i] ${msg}`); },

    /**
     * Logs a warning message.
     * @param msg - The message to log.
     */
    warn: (msg: string): void => { if (enabled) console.warn(`[!] ${msg}`); },

    /**
     * Logs an error message. Always logged, regardless of verbose mode.
     * @param msg - The message to log.
     */
    error: (msg: string): void => { console.error(`[-] ${msg}`); },
};
