import { FrookyAgent } from "../FrookyAgent";
import { LogEvent } from "./event/logEvent";

export type LogLevel = "none" | "error" | "warn" | "info" | "debug";
export type LogTo = "console" | "log";

/**
 * Sets the level of logging.
 * 0: No logging
 * 1: Errors only
 * 2: Errors + Warnings
 * 3: Errors + Warnings + Info
 * 4: Errors + Warnings + Info + Debug
 *
 * Will log using frooky messaging for logging by default.
 * If you want to use Frida `console` for logging, set `logTo = "console"`
 */
export class Logger {
  private logTo: LogTo;
  private verbosity: LogLevel;
  private frooky: FrookyAgent;

  private static readonly levelOrder: Record<LogLevel, number> = {
    none: 0,
    error: 1,
    warn: 2,
    info: 3,
    debug: 4,
  };

  private static readonly prefix: Record<LogLevel, string> = {
    none: "",
    debug: "[d]",
    info: "[i]",
    warn: "[!]",
    error: "[E]",
  };

  private static readonly levelColors: Record<LogLevel, string> = {
    none: "",
    info: "\x1b[34m", // blue
    warn: "\x1b[33m", // yellow
    error: "\x1b[31m", // red
    debug: "\x1b[32m", // green
  };

  private static readonly reset = "\x1b[0m";

  constructor(frooky: FrookyAgent, verbosity: LogLevel = "error", logTo: LogTo = "console") {
    this.frooky = frooky;
    this.verbosity = verbosity;
    this.logTo = logTo;
  }

  private shouldLog(level: LogLevel): boolean {
    return Logger.levelOrder[this.verbosity] >= Logger.levelOrder[level];
  }

  private format(level: LogLevel, msg: string | string[]): string {
    const p = Logger.prefix[level];
    if (Array.isArray(msg)) {
      const lines = msg.map((m) => `    ${m}`).join("\n");
      return `[${level}]:\n${lines}`;
    }
    return `[${level}] ${msg}`;
  }

  private emit(level: LogLevel, msg: string | string[]): void {
    if (!this.shouldLog(level)) return;

    const formatted = this.format(level, msg);

    if (this.logTo === "console") {
      const color = Logger.levelColors[level];
      const out = color + formatted + Logger.reset;
      switch (level) {
        case "info":
          console.log(out);
          break;
        case "warn":
          console.warn(out);
          break;
        case "error":
          console.error(out);
          break;
        case "debug":
          console.debug(out);
          break;
        default:
          console.log(out);
          break;
      }
    } else if (this.logTo === "log") {
      this.frooky.addEventToLog(new LogEvent(level, formatted));
    }
  }

  public debug(msg: string | string[]): void {
    this.emit("debug", msg);
  }
  public info(msg: string | string[]): void {
    this.emit("info", msg);
  }
  public warn(msg: string | string[]): void {
    this.emit("warn", msg);
  }
  public error(msg: string | string[]): void {
    this.emit("error", msg);
  }
}
