import type { FrookyConfig, Platform } from "frooky";
import type { BaseEvent } from "./shared/event/BaseEvent";
import type { HookEvent } from "./shared/event/HookEvent";
import { LogEvent } from "./shared/event/LogEvent";
import type { SummaryEvent } from "./shared/event/SummaryEvent";
import { Logger, type logTo } from "./shared/Logger";
import { validateFrookyConfig } from "./shared/validator/configValidator";
import { HookStore } from "shared/hook/HookStore";

declare global {
  var frooky: FrookyApp;
}

/**
 * Main application class for Frooky.
 * Manages configuration, events, and lifecycle of a frooky session.
 */
export class FrookyApp {
  private eventCache: BaseEvent[] = [];
  private platform: Platform;
  private hookStore: HookStore = new HookStore();

  /** Logger instance for this for frooky. */
  public log: Logger;
  public verbosity: number;


  /**
   * @param platform - The target platform to instrument.
   * @param verbosity - Log verbosity level (default: `3`).
   * @param logTo - Log destination (default: `"device"`).
   */
  constructor(platform: Platform, verbosity: number = 3, logTo: logTo = "device") {
    this.platform = platform;
    this.verbosity = verbosity;

    // setup logger
    this.log = new Logger(this, verbosity, logTo)
    this.log.info("Logging initialized")

    // printing some context infos
    this.log.info("Initializing frooky");
    this.log.info(`Target platform: ${this.platform}`);
    this.log.info(`Frida version:  ${Frida.version}`);
    this.log.info(`Target process:\n${JSON.stringify(Process, null, 2)}}`);
  }

  /**
   * Validates and registers a {@link FrookyConfig}.
   *
   * @param frookyConfig - The configuration to add.
   */
  public loadFrookyConfig(frookyConfig: FrookyConfig){
    this.log.info("Loading frooky configuration.")
    const { metadata, hookParsingResult } = validateFrookyConfig(frookyConfig, this.platform);

    this.log.info("Adding valid hook and their metadata to the hook store.")
    this.hookStore.addHooks(hookParsingResult.validHooks, metadata);





  }

  /** Starts the Frooky instrumentation session. */
  public run() {
    this.log.info("Starting frooky")
  }

  /**
   * Adds an event to the internal event cache.
   *
   * @param event - The event to cache.
   */
  public addEvent(event: LogEvent | HookEvent | SummaryEvent): void {
    if (!(event instanceof LogEvent)) {
      this.log.info(`Adding event to event cache: ${event}`);
    }
    this.eventCache.push(event);
  }
}
