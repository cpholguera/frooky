import type { FrookyApp } from "../Frooky";
import { LogEvent } from "./event/LogEvent";

export type LogLevel = "info" | "warn" | "error";

/**
 * Sets the level of logging.
 * 0: No logging
 * 1: Errors only
 * 2: Errors + Warnings
 * 3: Errors + Warnings + Info
 */
export class Logger {
    private deviceLoggingEnabled: boolean = false;
    private verbosity: number = 0;
    private frooky: FrookyApp;

    constructor(frooky: FrookyApp, verbosity: number = 0, deviceLoggingEnabled: boolean = false) {
        this.frooky = frooky;
        this.verbosity = verbosity;
        this.deviceLoggingEnabled = deviceLoggingEnabled;
    }

    private emit(level: LogLevel, msg: string): void {
        if (this.deviceLoggingEnabled) {
            switch (level) {
                case "info":  console.log(`[i] ${msg}`);   break;
                case "warn":  console.warn(`[!] ${msg}`);  break;
                case "error": console.error(`[-] ${msg}`); break;
            }
        } else {
            this.frooky.addEvent(new LogEvent(level, msg))            
        }
    }

    public info(msg: string):  void { if (this.verbosity >= 3) this.emit("info",  msg); }
    public warn(msg: string):  void { if (this.verbosity >= 2) this.emit("warn",  msg); }
    public error(msg: string): void { if (this.verbosity >= 1) this.emit("error", msg); }
}
