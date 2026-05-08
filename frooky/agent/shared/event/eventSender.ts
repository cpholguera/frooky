// takes care of event cache and sending events to the host

import { SEND_INTERVAL_MS } from "../defaultValues";
import type { BaseEvent } from "./baseEvent";

let senderInterval: ReturnType<typeof setInterval> | null = null;

export function startAsyncSender(eventCache: BaseEvent[], sendInterval: number = SEND_INTERVAL_MS): void {
  if (senderInterval !== null) {
    return; // already running
  }

  senderInterval = setInterval(() => {
    if (eventCache.length === 0) return;

    const eventsToSend = eventCache.splice(0, eventCache.length);

    try {
      send(eventsToSend);
    } catch (error) {
      console.error(`Failed to send events: ${error}`);
      eventCache.unshift(...eventsToSend);
    }
  }, sendInterval);
}

export function stopAsyncSender(): void {
  if (senderInterval !== null) {
    clearInterval(senderInterval);
    senderInterval = null;
  }
}
