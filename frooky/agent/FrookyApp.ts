import type { FrookyConfig, Platform } from "frooky";
import type { BaseEvent } from "./shared/event/baseEvent";
import { startAsyncSender } from "./shared/event/eventSender";
import type { HookEvent } from "./shared/event/hookEvent";
import type { LogEvent } from "./shared/event/logEvent";
import type { SummaryEvent } from "./shared/event/summaryEvent";
import type { HookRunner } from "./shared/hook/hookRunner";
import { HookStore } from "./shared/hook/hookStore";
import { NativeHookRunner } from "./shared/hook/nativeHookRunner";
import { Logger, type logTo } from "./shared/logger";
import { validateFrookyConfig } from "./shared/validator/configValidator";

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
  private platformHookRunner: HookRunner;
  private nativeHookRunner: NativeHookRunner;

  /** Logger instance for this for frooky. */
  public log: Logger;
  public verbosity: number;

  /**
   * @param platform - The target platform to instrument.
   * @param verbosity - Log verbosity level (default: `3`).
   * @param logTo - Log destination (default: `"device"`).
   */
  constructor(platform: Platform, platformHookRunner: HookRunner, verbosity: number = 3, logTo: logTo = "device") {
    //initialize asynchronous sender
    startAsyncSender(this.eventCache);

    this.platform = platform;
    this.platformHookRunner = platformHookRunner;
    this.nativeHookRunner = new NativeHookRunner();
    this.verbosity = verbosity;

    // setup logger
    this.log = new Logger(this, verbosity, logTo);
    this.log.info("Logging initialized");

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
  public loadFrookyConfig(frookyConfig: FrookyConfig) {
    this.log.info("Loading frooky configuration.");

    // validating frooky config
    const hookParsingResult = validateFrookyConfig(frookyConfig, this.platform);
    this.log.info("Adding valid hook and their metadata to the hook store.");

    // adding valid metadata and hooks to the hook store
    this.hookStore.addHooks(hookParsingResult.validHooks);
    this.log.info(`Added the following hooks to the store: \n${this.hookStore.prettyPrintHooks()}`);
  }

  // public prepareHookOperation() {
  //   if (this.platform === "Android") {
  //     this.platformHookRunner.operationsBuilder(this.hookStore.getJavaHooks());
  //   }
  //   if (this.platform === "iOS") {
  //     this.platformHookRunner.operationsBuilder(this.hookStore.getObjcHooks());
  //   }
  //   // run native hook on both platforms
  //   this.nativeHookRunner.operationsBuilder(this.hookStore.getNativeHooks());
  // }

  public executeHookOperations() {
    if (this.platform === "Android") {
      this.platformHookRunner.executeHooking(this.hookStore.getJavaHooks());
    }
    // if (this.platform === "iOS") {
    //   this.platformHookRunner.executeHooking(this.hookStore.getObjcHookOperations());
    // }
    // run native hook on both platforms
    this.nativeHookRunner.executeHooking(this.hookStore.getNativeHooks());
  }

  /**
   * Adds an event to the internal event cache.
   *
   * @param event - The event to cache.
   */
  public addEvent(event: LogEvent | HookEvent | SummaryEvent): void {
    this.eventCache.push(event);
  }
}
