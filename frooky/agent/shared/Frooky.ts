import type { FrookyConfig } from "frooky";
import type { BaseEvent } from "./event/BaseEvent";
import { enableLogging, log } from "./logger";

type Platform = "android" | "ios"

declare global {
  var frooky: FrookyApp;
}

export class FrookyApp {
  private eventCache: BaseEvent[] = [];
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

  loadFrookyConfig(frookyConfig: FrookyConfig){
    log.info("Loading frooky configuration")
    log.info(`  Metadata: ${JSON.stringify(frookyConfig.metadata)}`)
    log.info(`  Hooks: ${JSON.stringify(frookyConfig.hooks)}`)
  }

  run() {
    log.info("Starting frooky")
  }

  addEvent(event: BaseEvent): void {
    log.info(`Adding event to event cache: ${event}`);
    this.eventCache.push(event);
  }
}
