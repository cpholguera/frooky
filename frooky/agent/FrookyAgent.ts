import { NativeHookManager } from "./native/hook/nativeHookManager";
import { NativeHookValidator } from "./native/hook/nativeHookValidator";
import { validateAndRepairFrookyConfig } from "./shared/configValidator";
import { DEFAULT_SETTING_LOG_LEVEL, DEFAULT_SETTING_LOG_TO, DEFAULT_SETTING_RESOLVER_TIMEOUT_SECONDS } from "./shared/defaultValues";
import { BaseEvent } from "./shared/event/baseEvent";
import { startAsyncSender } from "./shared/event/eventSender";
import { HookEvent } from "./shared/event/hookEvent";
import { LogEvent } from "./shared/event/logEvent";
import { InputFrookyConfig } from "./shared/frookyConfig";
import { Platform } from "./shared/frookyMetadata";
import { FrookySettings } from "./shared/frookySettings";
import { HookManager } from "./shared/hook/hookManager";
import { HookValidator } from "./shared/hook/hookValidator";
import { Logger, LogLevel, LogTo } from "./shared/logger";

declare global {
  var frooky: FrookyAgent;
}

/**
 * Main application class for Frooky.
 * Manages configuration, events, and lifecycle of a frooky session.
 */
export class FrookyAgent {
  private eventCache: BaseEvent[] = [];
  private platform: Platform;
  private platformHookValidator: HookValidator<any, any>;
  private platformHookManger: HookManager<any, any>;
  private nativeHookValidator = new NativeHookValidator();
  private nativeHookManager = new NativeHookManager();
  private resolverTimeoutSeconds: number;

  /** Logger instance for this for frooky. */
  public log: Logger;

  /**
   * @param platform - The target platform to instrument.
   * @param verbosity - Log verbosity level (default: `3`).
   * @param logTo - Log destination (default: `"device"`).
   */
  constructor(
    platform: Platform,
    platformInputHookValidator: HookValidator<any, any>,
    platformHookResolver: HookManager<any, any>,
    logLevel: LogLevel = DEFAULT_SETTING_LOG_LEVEL,
    logTo: LogTo = DEFAULT_SETTING_LOG_TO,
    resolverTimeoutSeconds: number = DEFAULT_SETTING_RESOLVER_TIMEOUT_SECONDS,
  ) {
    //initialize asynchronous sender
    startAsyncSender(this.eventCache);

    this.platform = platform;
    this.platformHookValidator = platformInputHookValidator;
    this.platformHookManger = platformHookResolver;
    this.resolverTimeoutSeconds = resolverTimeoutSeconds;

    // setup logger
    this.log = new Logger(this, logLevel, logTo);
    this.log.info("Logger initialized");

    // printing some context infos
    this.log.info("Initializing frooky");
    this.log.info(`Declared target platform: ${this.platform}`);
    this.log.info(`Target platform: ${Process.platform}`);
    this.log.info(`Target frida version: ${Frida.version}`);
    this.log.info(`Target arch: ${Process.arch}`);
    this.log.debug(`Target process:\n${JSON.stringify(Process, null, 2)}}`);
  }

  /**
   * Loads hook config, resolves its hooks and runs them
   *
   * @param inputFrookyConfigs - The frooky config to add.
   */
  public async loadFrookyConfigs(inputFrookyConfigs: InputFrookyConfig[]) {
    for (const inputFrookyConfig of inputFrookyConfigs) {
      try {
        await this.loadFrookyConfig(inputFrookyConfig);
      } catch (e) {
        this.log.error(`Error during loading of the frooky config: ${String(e)}`);
      }
    }
  }

  /**
   * Validates and registers a {@link InputFrookyConfig}.
   *
   * @param inputFrookyConfig - The configuration to add.
   */
  public async loadFrookyConfig(inputFrookyConfig: InputFrookyConfig) {
    this.log.debug("Loading frooky configuration.");

    // validate frooky config
    this.log.debug("Validating frooky configuration");
    let validFrookyConfig: InputFrookyConfig;
    try {
      validFrookyConfig = validateAndRepairFrookyConfig(inputFrookyConfig, this.platform);
    } catch (e) {
      frooky.log.warn(`Skipping frooky config: ${e}`);
      return;
    }

    const validatedFrookySettings = validFrookyConfig.settings as FrookySettings;

    // validate the platform hooks
    this.log.debug(`Validating '${this.platform}' hooks`);
    const validPlatformHooks = this.platformHookValidator.validateAndNormalizeHooks(inputFrookyConfig, validatedFrookySettings);

    this.log.debug(`Validating 'native' hooks`);
    const validNativeHook = this.nativeHookValidator.validateAndNormalizeHooks(inputFrookyConfig, validatedFrookySettings);

    // preparing stats
    const countDeclaredPlatformHooks = validPlatformHooks.length;
    const countDeclaredNativeHooks = validNativeHook.length;
    let countSuccessfulPlatformHooks = 0;
    let countSuccessfulNativeHooks = 0;

    // async resolve platform hooks and register them
    const platformPromises = this.platformHookManger
      .resolveHooks(validPlatformHooks, this.resolverTimeoutSeconds)
      .then((platformHookPromises) => {
        return Promise.allSettled(
          platformHookPromises.map((platformHookPromise) =>
            platformHookPromise.then((platformHooks) => {
              if (platformHooks) {
                countSuccessfulPlatformHooks += this.platformHookManger.registerHooks(platformHooks);
              }
            }),
          ),
        );
      })
      .catch((e) => {
        this.log.error(`Error while resolving platform hooks: ${String(e)}`);
      });

    // async resolve native hooks and register them
    const nativePromises = this.nativeHookManager
      .resolveHooks(validNativeHook, this.resolverTimeoutSeconds)
      .then((nativeHookPromises) => {
        return Promise.allSettled(
          nativeHookPromises.map((nativeHookPromise) =>
            nativeHookPromise.then((nativeHooks) => {
              if (nativeHooks) {
                countSuccessfulNativeHooks += this.nativeHookManager.registerHooks(nativeHooks);
              }
            }),
          ),
        );
      })
      .catch((e) => {
        this.log.error(`Error while resolving native hooks: ${String(e)}`);
      });

    const configName = inputFrookyConfig.metadata?.name;
    const nameSuffix = configName ? ` '${configName}'` : "";
    const hookSuffix = configName ? ` from frooky configuration '${configName}'` : "";

    this.log.info(`Frooky configuration${nameSuffix} successfully parsed`);

    await Promise.all([
      Promise.all([platformPromises]).then(() => {
        if (countDeclaredPlatformHooks > 0) {
          this.log.info(`Successfully hooked ${countSuccessfulPlatformHooks}/${countDeclaredPlatformHooks} ${this.platform} methods${hookSuffix}`);
        }
      }),
      Promise.all([nativePromises]).then(() => {
        if (countDeclaredNativeHooks > 0) {
          this.log.info(`Successfully hooked ${countSuccessfulNativeHooks}/${countDeclaredNativeHooks} native functions${hookSuffix}`);
        }
      }),
    ]);
  }

  /**
   * Adds an event to the internal event cache.
   *
   * @param event - The event to cache.
   */
  public addEventToLog(event: LogEvent | HookEvent): void {
    this.eventCache.push(event);
  }
}
