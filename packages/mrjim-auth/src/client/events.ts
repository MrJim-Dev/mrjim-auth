import type { AuthChangeEvent, Session } from "../shared/types.js";
import { safeArrayIsArray } from "../shared/safe-intrinsics.js";
import { captureMethod, invoke, snapshotJson, freeze, ownData } from "./boundary.js";

const eventsGlobal = globalThis as unknown as Record<string, unknown>;
const eventsObjectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const eventsReflectConstruct = Reflect.construct;
const eventsReflectApply = Reflect.apply;
const eventsArrayPush = Array.prototype.push;
const eventsArraySplice = Array.prototype.splice;
const eventsArraySlice = Array.prototype.slice;
const eventsNumberIsSafeInteger = Number.isSafeInteger;
const eventsBrowserRuntime = (() => {
  try {
    return eventsGlobal.window === globalThis && typeof eventsGlobal.document === "object";
  } catch {
    return false;
  }
})();
const eventsBroadcastChannel = eventsBrowserRuntime ? eventsGlobal.BroadcastChannel : undefined;
const eventsMessageDataGetter = (() => {
  try {
    const constructor = eventsGlobal.MessageEvent;
    if (typeof constructor !== "function") return null;
    const descriptor = eventsObjectGetOwnPropertyDescriptor(constructor.prototype as object, "data");
    return descriptor !== undefined && typeof descriptor.get === "function" ? descriptor.get : null;
  } catch {
    return null;
  }
})();
const eventsStorageGetters = (() => {
  try {
    const constructor = eventsGlobal.StorageEvent;
    if (typeof constructor !== "function") return null;
    const key = eventsObjectGetOwnPropertyDescriptor(constructor.prototype as object, "key")?.get;
    const newValue = eventsObjectGetOwnPropertyDescriptor(constructor.prototype as object, "newValue")?.get;
    return typeof key === "function" && typeof newValue === "function" ? { key, newValue } : null;
  } catch {
    return null;
  }
})();
const eventsWindowListeners = (() => {
  try {
    const add = captureMethod(eventsGlobal as object, "addEventListener", "global.addEventListener");
    const remove = captureMethod(eventsGlobal as object, "removeEventListener", "global.removeEventListener");
    return { add, remove };
  } catch {
    return null;
  }
})();

export type AuthStateCallback = (event: AuthChangeEvent, session: Session | null) => void;
export interface AuthSubscription {
  readonly unsubscribe: () => void;
}

export interface EventBus {
  readonly subscribe: (callback: AuthStateCallback) => AuthSubscription;
  readonly dispatch: (event: AuthChangeEvent, session: Session | null) => void;
  readonly publish: (event: AuthChangeEvent, revision: number) => void;
  readonly dispose: () => void;
}

interface RemoteMessage {
  readonly version: 1;
  readonly revision: number;
  readonly event: AuthChangeEvent;
}

function eventProperty(event: object, key: "data" | "key" | "newValue"): { readonly ok: boolean; readonly present: boolean; readonly value: unknown } {
  const own = ownData(event, key);
  if (!own.ok || own.present) return own;
  const getter = key === "data"
    ? eventsMessageDataGetter
    : key === "key"
      ? eventsStorageGetters?.key ?? null
      : eventsStorageGetters?.newValue ?? null;
  if (getter === null) return own;
  try {
    return { ok: true, present: true, value: eventsReflectApply(getter, event, []) };
  } catch {
    return { ok: false, present: false, value: undefined };
  }
}

function safeDebug(debug: ((message: string, context?: unknown) => void) | undefined, message: string, context: Record<string, unknown>): void {
  if (debug === undefined) return;
  try {
    debug(message, context);
  } catch {
    // Observability callbacks cannot affect lifecycle delivery.
  }
}

function isEvent(value: unknown): value is AuthChangeEvent {
  return value === "INITIAL_SESSION" || value === "SIGNED_IN" || value === "SIGNED_OUT" || value === "TOKEN_REFRESHED" || value === "USER_UPDATED" || value === "PASSWORD_RECOVERY";
}

function parseMessage(value: unknown): RemoteMessage | null {
  try {
    const snapshot = snapshotJson(value, "cross-tab event");
    if (snapshot === null || typeof snapshot !== "object" || safeArrayIsArray(snapshot)) return null;
    const version = ownData(snapshot, "version");
    const revision = ownData(snapshot, "revision");
    const event = ownData(snapshot, "event");
    if (!version.ok || !version.present || version.value !== 1 || !revision.ok || !revision.present || typeof revision.value !== "number" || !eventsNumberIsSafeInteger(revision.value) || revision.value < 0 || !event.ok || !event.present || !isEvent(event.value)) return null;
    return { version: 1, revision: revision.value, event: event.value };
  } catch {
    return null;
  }
}

export function createEventBus(options: {
  readonly channelName: string;
  readonly storageKey: string;
  readonly debug?: ((message: string, context?: unknown) => void) | undefined;
  readonly onRemote: (event: AuthChangeEvent, revision: number) => void;
}): EventBus {
  const subscriptions: AuthStateCallback[] = [];
  let disposed = false;
  let channel: object | null = null;
  let channelPost: Function | null = null;
  let channelClose: Function | null = null;
  let channelRemove: Function | null = null;
  let storageListening = false;
  const storageListener = (event: unknown): void => {
    if (disposed || event === null || typeof event !== "object") return;
    const key = eventProperty(event, "key");
    const newValue = eventProperty(event, "newValue");
    if (!key.ok || !key.present || key.value !== options.storageKey || !newValue.ok || !newValue.present) return;
    if (newValue.value !== null && typeof newValue.value !== "string") return;
    options.onRemote("SIGNED_IN", 0);
  };
  const messageListener = (event: unknown): void => {
    if (disposed || event === null || typeof event !== "object") return;
    const data = eventProperty(event, "data");
    if (!data.ok || !data.present) return;
    const message = parseMessage(data.value);
    if (message !== null) options.onRemote(message.event, message.revision);
  };

  if (typeof eventsBroadcastChannel === "function") {
    try {
      channel = eventsReflectConstruct(eventsBroadcastChannel as Function, [options.channelName], eventsBroadcastChannel as Function) as object;
      const add = captureMethod(channel, "addEventListener", "BroadcastChannel.addEventListener");
      const post = captureMethod(channel, "postMessage", "BroadcastChannel.postMessage");
      const close = captureMethod(channel, "close", "BroadcastChannel.close");
      channelPost = post.method;
      channelClose = close.method;
      const remove = captureMethod(channel, "removeEventListener", "BroadcastChannel.removeEventListener");
      channelRemove = remove.method;
      invoke(add.method, add.receiver, ["message", messageListener]);
    } catch {
      channel = null;
      channelPost = null;
      channelClose = null;
      channelRemove = null;
      safeDebug(options.debug, "broadcast channel unavailable", { source: "broadcast" });
    }
  }

  if (channel === null && eventsWindowListeners !== null) {
    try {
      invoke(eventsWindowListeners.add.method, eventsWindowListeners.add.receiver, ["storage", storageListener]);
      storageListening = true;
    } catch {
      safeDebug(options.debug, "storage listener unavailable", { source: "storage" });
    }
  }

  const subscribe = (callback: AuthStateCallback): AuthSubscription => {
    if (disposed || typeof callback !== "function") return freeze({ unsubscribe: () => undefined });
    eventsArrayPush.call(subscriptions, callback);
    let active = true;
    const unsubscribe = (): void => {
      if (!active) return;
      active = false;
      for (let index = 0; index < subscriptions.length; index += 1) {
        if (subscriptions[index] === callback) {
          eventsArraySplice.call(subscriptions, index, 1);
          break;
        }
      }
    };
    return freeze({ unsubscribe });
  };

  const dispatch = (event: AuthChangeEvent, session: Session | null): void => {
    if (disposed) return;
    const callbacks = eventsArraySlice.call(subscriptions) as AuthStateCallback[];
    for (let index = 0; index < callbacks.length; index += 1) {
      const callback = callbacks[index];
      if (callback === undefined) continue;
      try {
        callback(event, session);
      } catch {
        safeDebug(options.debug, "auth state callback failed", { event });
      }
    }
  };

  const publish = (event: AuthChangeEvent, revision: number): void => {
    if (disposed || channel === null || channelPost === null) return;
    const message: RemoteMessage = { version: 1, revision, event };
    try {
      invoke(channelPost, channel, [message]);
    } catch {
      safeDebug(options.debug, "broadcast event failed", { event });
    }
  };

  const dispose = (): void => {
    if (disposed) return;
    disposed = true;
    subscriptions.length = 0;
    if (storageListening && eventsWindowListeners !== null) {
      try {
        invoke(eventsWindowListeners.remove.method, eventsWindowListeners.remove.receiver, ["storage", storageListener]);
      } catch {
        // Disposal is idempotent and fail-closed.
      }
    }
    if (channel !== null) {
      try {
        if (channelRemove !== null) invoke(channelRemove, channel, ["message", messageListener]);
        if (channelClose !== null) invoke(channelClose, channel, []);
      } catch {
        // Disposal is idempotent and fail-closed.
      }
    }
    channel = null;
    channelPost = null;
    channelClose = null;
    channelRemove = null;
    storageListening = false;
  };

  return freeze({ subscribe, dispatch, publish, dispose });
}
