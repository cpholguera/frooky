import { runFrookyAgent as runFrookyAgentAndroid } from "android/legacy/android-agent";
import { runFrookyAgent as runFrookyAgentIOS } from "ios/legacy/ios-agent";
import type { BaseEvent } from "./event/BaseEvent";
import { enableLogging, log } from "./logger";

interface FrookyApp {
  init(hooks: unknown, target: Target, verboseFlag?: boolean): void;
  addEvent(event: BaseEvent): void;
}

type Target = "android" | "ios" | "native"

declare global {
  var frooky: FrookyApp;
}

function createFrooky(): FrookyApp {

  // internal state
  const eventCache: BaseEvent[] = [];

  return {
    init(hooks: unknown, target: Target, verboseFlag: boolean = false) {

      if (verboseFlag){
        enableLogging();
      }

      log.info(`Initializing frooky`);

      if (target === "android") {
        runFrookyAgentAndroid(hooks);
      } else if (target === "ios") {
        runFrookyAgentIOS(hooks);
      }
    },

    addEvent(event) {
      log.info(`Adding event to event cache: ${event}`,);
      eventCache.push(event);
    },
  };
}

globalThis.frooky = createFrooky();