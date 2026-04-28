import type { FrookyApp } from "../FrookyApp";
import { LogEvent } from "./event/logEvent";

export type LogLevel = "info" | "warn" | "error";
export type logTo = "device" | "frooky";

const LEVEL_PREFIX: Record<LogLevel, string> = {
  info: "[i]",
  warn: "[!]",
  error: "[-]",
};

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

  constructor(frooky: FrookyApp, verbosity: number = 0, logTo: logTo = "frooky") {
    this.frooky = frooky;
    this.verbosity = verbosity;
    this.logTo = logTo;
  }

  private format(level: LogLevel, msg: string | string[]): string {
    const prefix = LEVEL_PREFIX[level];
    if (Array.isArray(msg)) {
      const lines = msg.map((m) => `    ${m}`).join("\n");
      return `${prefix} ${level}:\n${lines}`;
    }
    return `${prefix} ${msg}`;
  }

  private emit(level: LogLevel, msg: string | string[]): void {
    const formatted = this.format(level, msg);
    if (this.logTo === "device") {
      switch (level) {
        case "info":
          console.log(formatted);
          break;
        case "warn":
          console.warn(formatted);
          break;
        case "error":
          console.error(formatted);
          break;
      }
    } else if (this.logTo === "frooky") {
      this.frooky.addEvent(new LogEvent(level, formatted));
    }
  }

  public info(msg: string | string[]): void {
    if (this.verbosity >= 3) this.emit("info", msg);
  }
  public warn(msg: string | string[]): void {
    if (this.verbosity >= 2) this.emit("warn", msg);
  }
  public error(msg: string | string[]): void {
    if (this.verbosity >= 1) this.emit("error", msg);
  }
}
