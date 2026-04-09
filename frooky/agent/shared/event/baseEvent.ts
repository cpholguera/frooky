import { uuidv4 } from "../utils";

/**
 * Abstract class for all events created by frooky.
 *
 * Automatically populates {@link id} and {@link timestamp} on instantiation.
* ```
 */
export abstract class BaseEvent {
  /**
   * Unique identifier for the event.
   * Automatically generated as a UUIDv4 on instantiation.
   */
  readonly id: string = uuidv4();

  /**
   * ISO 8601 timestamp of when the event was created.
   * Automatically set to the current date and time on instantiation.
   */
  readonly timestamp: string = new Date().toISOString();
}
