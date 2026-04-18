import type { FrookyApp } from "../FrookyApp";
import { LogEvent } from "./event/logEvent";

export type LogLevel = "info" | "warn" | "error";
export type logTo = "device" | "frooky";

/**
 * Sets the level of logging.
 * 0: No logging
 * 1: Errors only
 * 2: Errors + Warnings
 * 3: Errors + Warnings + Info
 *
 * Will log using frooky messaging for logging by default.
 * If you want to use Frida `console` for logging, you set `logTo = "device"`
 */
export class Logger {
	private logTo: logTo;
	private verbosity: number;
	private frooky: FrookyApp;

	constructor(
		frooky: FrookyApp,
		verbosity: number = 0,
		logTo: logTo = "frooky",
	) {
		this.frooky = frooky;
		this.verbosity = verbosity;
		this.logTo = logTo;
	}

	private emit(level: LogLevel, msg: string): void {
		if (this.logTo === "device") {
			switch (level) {
				case "info":
					console.log(`[i] ${msg}`);
					break;
				case "warn":
					console.warn(`[!] ${msg}`);
					break;
				case "error":
					console.error(`[-] ${msg}`);
					break;
			}
		} else if (this.logTo === "frooky") {
			this.frooky.addEvent(new LogEvent(level, msg));
		}
	}

	public info(msg: string): void {
		if (this.verbosity >= 3) this.emit("info", msg);
	}
	public warn(msg: string): void {
		if (this.verbosity >= 2) this.emit("warn", msg);
	}
	public error(msg: string): void {
		if (this.verbosity >= 1) this.emit("error", msg);
	}
}
