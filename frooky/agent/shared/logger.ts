import { FrookyAgent } from "../FrookyAgent";
import { LogEvent } from "./event/logEvent";

export type LogLevel = "info" | "warn" | "error" | "debug";
export type LogTo = "device" | "frooky";

/**
 * Sets the level of logging.
 * 0: No logging
 * 1: Errors only
 * 2: Errors + Warnings
 * 3: Errors + Warnings + Info
 * 4: Errors + Warnings + Info + Debug
 *
 * Will log using frooky messaging for logging by default.
 * If you want to use Frida `console` for logging, you set `logTo = "device"`
 */
export class Logger {
  private logTo: LogTo;
  private verbosity: number;
  private frooky: FrookyAgent;

  constructor(frooky: FrookyAgent, verbosity: number = 0, logTo: LogTo = "frooky") {
    this.frooky = frooky;
    this.verbosity = verbosity;
    this.logTo = logTo;
  }

  private format(level: LogLevel, msg: string | string[]): string {
    const prefix: Record<LogLevel, string> = {
      debug: "[d]",
      info: "[i]",
      warn: "[!]",
      error: "[!]",
    };

    if (Array.isArray(msg)) {
      const lines = msg.map((m) => `    ${m}`).join("\n");
      return `${prefix[level]} ${level}:\n${lines}`;
    }
    return `${prefix[level]} ${msg}`;
  }

  private readonly levelColors: Record<LogLevel, string> = {
    info: "\x1b[34m", // blue
    warn: "\x1b[33m", // yellow
    error: "\x1b[31m", // red
    debug: "\x1b[32m", // green
  };

  private readonly reset = "\x1b[0m";

  private emit(level: LogLevel, msg: string | string[]): void {
    const formatted = this.format(level, msg);
    if (this.logTo === "device") {
      const color = this.levelColors[level];
      switch (level) {
        case "info":
          console.log(color + formatted + this.reset);
          break;
        case "warn":
          console.warn(color + formatted + this.reset);
          break;
        case "error":
          console.error(color + formatted + this.reset);
          break;
        case "debug":
          console.debug(color + formatted + this.reset);
          break;
      }
    } else if (this.logTo === "frooky") {
      this.frooky.addEvent(new LogEvent(level, formatted));
    }
  }

  public debug(msg: string | string[]): void {
    if (this.verbosity >= 4) this.emit("debug", msg);
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
