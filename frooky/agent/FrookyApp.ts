import type { FrookyConfig, Platform } from "frooky";
import type { BaseEvent } from "./shared/event/BaseEvent";
import type { HookEvent } from "./shared/event/HookEvent";
import { LogEvent } from "./shared/event/LogEvent";
import type { SummaryEvent } from "./shared/event/SummaryEvent";
import { Logger, type logTo } from "./shared/Logger";
import { validateFrookyConfig } from "./shared/validator/frookyConfigValidator";

declare global {
  var frooky: FrookyApp;
}

export class FrookyApp {
  private eventCache: BaseEvent[] = [];
  private frookyConfigs: FrookyConfig[] = [];
  private platform: Platform;
  
  public log: Logger;

  constructor(platform: Platform, verbosity: number = 3, logTo: logTo = "device") {
    this.platform = platform;

    // setup logger
    this.log = new Logger(this, verbosity, logTo)
    this.log.info("Logging initialized")

    this.log.info("Initializing frooky");
    this.log.info(`  Target platform: ${this.platform}`);
    this.log.info(`  Frida version:  ${Frida.version}`);
    const json = JSON.stringify(Process, null, 2).replace(/\n/g, '\n        ');
    this.log.info(`  Target process:\n        ${json}`);
  }

  public addFrookyConfig(frookyConfig: FrookyConfig){
    this.log.info("Loading frooky configuration...")

    try {
      validateFrookyConfig(frookyConfig, this.platform)
      this.frookyConfigs.push(frookyConfig)
    } catch {
      this.log.error("frooky configuration is not valid.")
    }
  }

  public run() {
    this.log.info("Starting frooky")
  }

  public addEvent(event: LogEvent | HookEvent | SummaryEvent): void {
    if (!(event instanceof LogEvent)) {
      this.log.info(`Adding event to event cache: ${event}`);
    }
    this.eventCache.push(event);
  }
}
