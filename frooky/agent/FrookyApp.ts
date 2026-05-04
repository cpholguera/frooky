import type { FrookyConfig } from "frooky";
import { NativeHookResolver } from "./native/hook/nativeHookResolver";
import { NativeHookValidator } from "./native/hook/nativeHookValidator";
import { validateConfig } from "./shared/configValidator";
import { BaseEvent } from "./shared/event/baseEvent";
import { startAsyncSender } from "./shared/event/eventSender";
import { HookEvent } from "./shared/event/hookEvent";
import { LogEvent } from "./shared/event/logEvent";
import type { Platform } from "./shared/frookyMetadata";
import { Hook } from "./shared/hook/hook";
import { HookResolver } from "./shared/hook/hookResolver";
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
  private platformHookValidator: HookValidator<any, any, any>;
  private platformHookResolver: HookResolver<any, any>;
  private nativeHookValidator: NativeHookValidator = new NativeHookValidator();
  private nativeHookResolver: NativeHookResolver = new NativeHookResolver();

  /** Internal hook store  */
  private hookStore: Hook[] = [];

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
    platformInputHookValidator: HookValidator<any, any, any>,
    platformHookResolver: HookResolver<any, any>,
    verbosity: number = 3,
    logTo: logTo = "device",
  ) {
    //initialize asynchronous sender
    startAsyncSender(this.eventCache);

    this.platform = platform;
    this.platformHookValidator = platformInputHookValidator;
    this.platformHookResolver = platformHookResolver;

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
   * @param inputFrookyConfig - The configuration to add.
   */
  public async loadFrookyConfig(inputFrookyConfig: FrookyConfig) {
    this.log.info("Loading frooky configuration.");

    // validate frooky config
    this.log.info("Validating frooky configuration.");
    const { globalHookSettings, globalDecoderSettings } = validateConfig(inputFrookyConfig, this.platform);

    // validate the platform hooks (java or objc)
    this.log.info(`Validating '${this.platform}' hooks.`);
    const validPlatformHooks = this.platformHookValidator.validateHooks(inputFrookyConfig, globalHookSettings, globalDecoderSettings);

    this.log.info(`Validating 'native' hooks.`);
    const validNativeHook = this.nativeHookValidator.validateHooks(inputFrookyConfig, globalHookSettings, globalDecoderSettings);

    //resolve valid platform hooks
    const platformPromises = this.platformHookResolver.resolveInputHooks(validPlatformHooks).then((platformHooks) => {
      this.hookStore.push(...platformHooks);
    });

    // resolve valid native hooks
    const nativePromises = this.nativeHookResolver.resolveInputHooks(validNativeHook).then((nativeHooks) => {
      this.hookStore.push(...nativeHooks);
    });

    // Wait for all to finish
    await Promise.all([platformPromises, nativePromises]).catch((e) => {
      this.log.error(`Error while resolving hooks: ${String(e)}`);
    });

    frooky.log.info(`${this.platform} and native hooks resolved and stored.`);
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
