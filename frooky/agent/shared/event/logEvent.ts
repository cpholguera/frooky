import { BaseEvent, LogLevel } from "frooky/shared";
/**
 * Class representing a log event created by frooky.
 *
 */
export class LogEvent extends BaseEvent {
  readonly type = "log" as const;

  readonly level: LogLevel;

  readonly msg: string;

  constructor(level: LogLevel, msg: string) {
    super();
    this.level = level;
    this.msg = msg;
  }
}
