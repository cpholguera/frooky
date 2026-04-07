import type { FrookyConfig, Platform } from "frooky";
import type { BaseEvent } from "./event/BaseEvent";
import { enableLogging, log } from "./logger";
import { validateFrookyConfig } from "./validator/frookyConfigValidator";


declare global {
  var frooky: FrookyApp;
}

export class FrookyApp {
  private eventCache: BaseEvent[] = [];
  private frookyConfigs: FrookyConfig[] = [];
  private platform: Platform;

  constructor(platform: Platform, enableLoggingFlag: boolean = false) {
    this.platform = platform;

    if (enableLoggingFlag) {
      enableLogging();
      log.info("Logging enabled");
    }

    log.info("Initializing frooky");
    log.info(`Target platform: ${this.platform}`);
  }

  public addFrookyConfig(frookyConfig: FrookyConfig){
    log.info("Loading frooky configuration...")

    try {
      validateFrookyConfig(frookyConfig, this.platform)
      this.frookyConfigs.push(frookyConfig)
    } catch {
      console.error("frooky configuration is not valid.")
    }
  }

  public run() {
    log.info("Starting frooky")
  }

  public addEvent(event: BaseEvent): void {
    log.info(`Adding event to event cache: ${event}`);
    this.eventCache.push(event);
  }
}
