export type NativeHookEvent = {
  id: string;
  type: "native-hook";
  category: string;
  time: string;
  module: string;
  symbol: string;
  address: string;
  stackTrace: string[];
  inputParameters: any[];
};

export type JavaHookEvent = {
  id: string;
  type: "hook";
  category: string;
  time: string;
  class: string;
  method: string;
  instanceId: string;
  stackTrace: string[];
  inputParameters: any[];
  returnValue?: any[];
};

export type NativeFilterSuppressed = {
  type: "native-filter-suppressed";
  symbol: string;
  args: any[];
};

export type HookEvent = NativeHookEvent | JavaHookEvent;

export type NativeSummary = {
  type: "native-summary";
  hooks: any[];
  totalHooks: number;
  errors: any[];
  totalErrors: number;
};

export type JavaSummary = {
  type: "summary";
  hooks: any[];
  totalHooks: number;
  errors: any[];
  totalErrors: number;
};

export type Summary = NativeSummary | JavaSummary;

export namespace messaging {
  export function sendEvent(event: HookEvent): void {
    send(event);
  }

  export function sendSummary(summary: Summary): void {
    send(summary);
  }

}