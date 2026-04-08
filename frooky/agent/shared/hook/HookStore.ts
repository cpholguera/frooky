import { Hook, HookMetadata } from "frooky";

function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (a === null || b === null) return false;
  if (typeof a !== "object" || typeof b !== "object") return false;

  const keysA = Object.keys(a as object);
  const keysB = Object.keys(b as object);

  if (keysA.length !== keysB.length) return false;

  return keysA.every((key) =>
    deepEqual(
      (a as Record<string, unknown>)[key],
      (b as Record<string, unknown>)[key]
    )
  );
}


export class HookStore {
  private hooks: Hook[] = [];
  private metadata: HookMetadata[] = [];
  // Maps hook index -> metadata index
  private linkMap: Map<number, number> = new Map();

  private findOrInsertMetadata(meta: HookMetadata): number {
    const existing = this.metadata.findIndex((m) =>
      deepEqual(m, meta)
    );
    if (existing !== -1) return existing;
    this.metadata.push(meta);
    return this.metadata.length - 1;
  }

  private insertHook(hook: Hook, metaIndex?: number): void {
    this.hooks.push(hook);

    if (metaIndex){
        const existing = this.hooks.findIndex((h) => deepEqual(h, hook));
        if (existing !== -1) {
        // Hook already exists, update its metadata link
        this.linkMap.set(existing, metaIndex);
        return;
        }
        this.linkMap.set(this.hooks.length - 1, metaIndex);
    }
  }
  

  addHook(hook: Hook, meta?: HookMetadata): void {
    if(meta){
        const metaIndex = this.findOrInsertMetadata(meta);
        this.insertHook(hook, metaIndex);
    } else {
        this.insertHook(hook);
    }
  }

  addHooks(hooks: Hook[], meta?: HookMetadata): void {
    if(meta){
        const metaIndex = this.findOrInsertMetadata(meta);
        for (const hook of hooks) {
        this.insertHook(hook, metaIndex);
        }
    } else {
        for (const hook of hooks) {
        this.insertHook(hook);
        }
    }
  }

  listHooks(): { hook: Hook; metadata: HookMetadata }[] {
    return this.hooks.map((hook, i) => ({
      hook,
      metadata: this.metadata[this.linkMap.get(i)!],
    }));
  }

  listMetadata(): HookMetadata[] {
    return [...this.metadata];
  }
}
