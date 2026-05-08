import type { FrookyConfig } from "frooky";
import { NativeHookManager } from "./native/hook/nativeHookManager";
import { NativeHookValidator } from "./native/hook/nativeHookValidator";
import { validateConfig } from "./shared/configValidator";
import { BaseEvent } from "./shared/event/baseEvent";
import { startAsyncSender } from "./shared/event/eventSender";
import { HookEvent } from "./shared/event/hookEvent";
import { LogEvent } from "./shared/event/logEvent";
import type { Platform } from "./shared/frookyMetadata";
import { HookManager } from "./shared/hook/hookManager";
import { HookValidator } from "./shared/hook/hookValidator";
import { Logger, type logTo } from "./shared/logger";

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
  private platformHookValidator: HookValidator<any, any>;
  private platformHookManger: HookManager<any, any>;
  private nativeHookValidator = new NativeHookValidator();
  private nativeHookManager = new NativeHookManager();

  /** Logger instance for this for frooky. */
  public log: Logger;
  public verbosity: number;

  /**
   * @param platform - The target platform to instrument.
   * @param verbosity - Log verbosity level (default: `3`).
   * @param logTo - Log destination (default: `"device"`).
   */
  constructor(
    platform: Platform,
    platformInputHookValidator: HookValidator<any, any>,
    platformHookResolver: HookManager<any, any>,
    verbosity: number = 3,
    logTo: logTo = "device",
  ) {
    //initialize asynchronous sender
    startAsyncSender(this.eventCache);

    this.platform = platform;
    this.platformHookValidator = platformInputHookValidator;
    this.platformHookManger = platformHookResolver;

    this.verbosity = verbosity;

    // setup logger
    this.log = new Logger(this, verbosity, logTo);
    this.log.info("Logger initialized");

    // printing some context infos
    this.log.info("Initializing frooky");
    this.log.info(`Target platform: ${this.platform}`);
    this.log.info(`Frida version:  ${Frida.version}`);
    this.log.info(`Target process:\n${JSON.stringify(Process, null, 2)}}`);
  }

  /**
   * Loads hook config, resolves its hooks and runs them
   *
   * @param inputFrookyConfig - The frooky config to add.
   */
  public async run(inputFrookyConfig: FrookyConfig) {
    try {
      await this.loadFrookyConfig(inputFrookyConfig);
    } catch (e) {
      console.error(`Error during loading of the frooky config: ${String(e)}`);
    }
  }

  /**
   * Validates and registers a {@link FrookyConfig}.
   *
   * @param inputFrookyConfig - The configuration to add.
   */
  public async loadFrookyConfig(inputFrookyConfig: FrookyConfig) {
    this.log.info("Loading frooky configuration.");

    // validate frooky config
    this.log.info("Validating frooky configuration.");
    const { globalHookSettings, globalDecoderSettings } = validateConfig(inputFrookyConfig, this.platform);

    // validate the platform hooks
    this.log.info(`Validating '${this.platform}' hooks.`);
    const validPlatformHooks = this.platformHookValidator.validateAndNormalizeHooks(inputFrookyConfig, globalHookSettings, globalDecoderSettings);

    this.log.info(`Validating 'native' hooks.`);
    const validNativeHook = this.nativeHookValidator.validateAndNormalizeHooks(inputFrookyConfig, globalHookSettings, globalDecoderSettings);

    // async resolve platform hooks and register them
    const platformPromises = this.platformHookManger
      .resolveHooks(validPlatformHooks, globalHookSettings.hookTimeout)
      .then((platformHookPromises) => {
        for (const platformHookPromise of platformHookPromises) {
          platformHookPromise.then((platformHooks) => {
            if (platformHooks) {
              this.platformHookManger.registerHooks(platformHooks);
            }
          });
        }
      })
      .catch((e) => {
        this.log.error(`Error while resolving native hooks: ${String(e)}`);
      });

    // async resolve native hooks and register them
    const nativePromises = this.nativeHookManager
      .resolveHooks(validNativeHook, globalHookSettings.hookTimeout)
      .then((nativeHookPromises) => {
        for (const nativeHookPromise of nativeHookPromises) {
          nativeHookPromise.then((nativeHooks) => {
            if (nativeHooks) {
              this.nativeHookManager.registerHooks(nativeHooks);
            }
          });
        }
      })
      .catch((e) => {
        this.log.error(`Error while resolving native hooks: ${String(e)}`);
      });

    // wait until all promises are resolved
    await Promise.all([platformPromises, nativePromises]);
  }

  /**
   * Adds an event to the internal event cache.
   *
   * @param event - The event to cache.
   */
  public addEvent(event: LogEvent | HookEvent): void {
    this.eventCache.push(event);
  }
}
