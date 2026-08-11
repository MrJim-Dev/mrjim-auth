/*
 * The shared contract is reachable from both browser and server entry points.
 * Capture the small set of language intrinsics used at public boundaries once,
 * before configured values are inspected. The documented trust model assumes
 * the module graph is loaded before application code mutates these globals;
 * post-import mutation is never consulted by the helpers below.
 */
const arrayConstructor = Array;
const arrayIsArray = Array.isArray;
const arraySome = Array.prototype.some;
const arrayIncludes = Array.prototype.includes;
const arrayMap = Array.prototype.map;
const arrayFilter = Array.prototype.filter;
const objectCreate = Object.create;
const objectDefineProperty = Object.defineProperty;
const objectFreeze = Object.freeze;
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const objectGetOwnPropertyNames = Object.getOwnPropertyNames;
const objectGetOwnPropertySymbols = Object.getOwnPropertySymbols;
const objectGetPrototypeOf = Object.getPrototypeOf;
const objectSetPrototypeOf = Object.setPrototypeOf;
const objectPrototype = Object.prototype;
const objectHasOwnProperty = Object.prototype.hasOwnProperty;
const reflectApply = Reflect.apply;
const numberIsFinite = Number.isFinite;
const numberIsInteger = Number.isInteger;
const numberIsSafeInteger = Number.isSafeInteger;
const setHas = Set.prototype.has;
const setAdd = Set.prototype.add;
const stringTrim = String.prototype.trim;
const stringReplace = String.prototype.replace;
const stringToLowerCase = String.prototype.toLowerCase;
const stringToUpperCase = String.prototype.toUpperCase;
const stringIncludes = String.prototype.includes;
const stringStartsWith = String.prototype.startsWith;
const stringEndsWith = String.prototype.endsWith;
const stringSlice = String.prototype.slice;
const stringSplit = String.prototype.split;
const stringNormalize = String.prototype.normalize;
const stringToString = String.prototype.toString;
const stringPadEnd = String.prototype.padEnd;
const typedArrayConstructor = Uint8Array;
const typedArrayFrom = Uint8Array.from;

export type SafeDataProperty =
  | { readonly valid: true; readonly present: false }
  | { readonly valid: true; readonly present: true; readonly value: unknown }
  | { readonly valid: false; readonly present: boolean };

export const safeObjectPrototype = objectPrototype;
export const safeArrayIsArray = (value: unknown): boolean => {
  try {
    return arrayIsArray(value);
  } catch {
    return false;
  }
};

export const safeNumberIsFinite = (value: unknown): value is number => {
  try {
    return numberIsFinite(value);
  } catch {
    return false;
  }
};

export const safeNumberIsInteger = (value: unknown): value is number => {
  try {
    return numberIsInteger(value);
  } catch {
    return false;
  }
};

export const safeNumberIsSafeInteger = (value: unknown): value is number => {
  try {
    return numberIsSafeInteger(value);
  } catch {
    return false;
  }
};

export function safeStringTrim(value: string): string | null {
  try {
    return reflectApply(stringTrim, value, []) as string;
  } catch {
    return null;
  }
}

export function safeStringReplace(value: string, search: string | RegExp, replacement: string): string | null {
  try {
    return reflectApply(stringReplace, value, [search, replacement]) as string;
  } catch {
    return null;
  }
}

export function safeStringToLowerCase(value: string): string | null {
  try {
    return reflectApply(stringToLowerCase, value, []) as string;
  } catch {
    return null;
  }
}

export function safeStringToUpperCase(value: string): string | null {
  try {
    return reflectApply(stringToUpperCase, value, []) as string;
  } catch {
    return null;
  }
}

export function safeStringIncludes(value: string, search: string): boolean {
  try {
    return reflectApply(stringIncludes, value, [search]) as boolean;
  } catch {
    return false;
  }
}

export function safeStringStartsWith(value: string, search: string): boolean {
  try {
    return reflectApply(stringStartsWith, value, [search]) as boolean;
  } catch {
    return false;
  }
}

export function safeStringEndsWith(value: string, search: string): boolean {
  try {
    return reflectApply(stringEndsWith, value, [search]) as boolean;
  } catch {
    return false;
  }
}

export function safeStringSlice(value: string, start: number, end?: number): string | null {
  try {
    return reflectApply(stringSlice, value, end === undefined ? [start] : [start, end]) as string;
  } catch {
    return null;
  }
}

export function safeStringSplit(value: string, separator: string): readonly string[] | null {
  try {
    const result = reflectApply(stringSplit, value, [separator]) as string[];
    return safeArrayCopy(result);
  } catch {
    return null;
  }
}

export function safeStringNormalize(value: string, form: "NFKC" | "NFC" = "NFKC"): string | null {
  try {
    return reflectApply(stringNormalize, value, [form]) as string;
  } catch {
    return null;
  }
}

export function safeStringPadEnd(value: string, length: number, fill = " "): string | null {
  try {
    return reflectApply(stringPadEnd, value, [length, fill]) as string;
  } catch {
    return null;
  }
}

export function safeStringValue(value: string): string | null {
  try {
    return reflectApply(stringToString, value, []) as string;
  } catch {
    return null;
  }
}

export function safeSetHasValue<T>(set: ReadonlySet<T>, value: T): boolean {
  try {
    return reflectApply(setHas, set, [value]) as boolean;
  } catch {
    return false;
  }
}

export function safeSetAddValue<T>(set: Set<T>, value: T): boolean {
  try {
    reflectApply(setAdd, set, [value]);
    return true;
  } catch {
    return false;
  }
}

export function safeArraySomeValue<T>(array: readonly T[], callback: (value: T, index: number) => boolean): boolean {
  try {
    return reflectApply(arraySome, array, [callback]) as boolean;
  } catch {
    return false;
  }
}

export function safeArrayIncludesValue<T>(array: readonly T[], value: T): boolean {
  try {
    return reflectApply(arrayIncludes, array, [value]) as boolean;
  } catch {
    return false;
  }
}

export function safeArrayMapValue<T, U>(array: readonly T[], callback: (value: T, index: number) => U): readonly U[] | null {
  try {
    return safeArrayCopy(reflectApply(arrayMap, array, [callback]) as U[]);
  } catch {
    return null;
  }
}

export function safeArrayFilterValue<T>(array: readonly T[], callback: (value: T, index: number) => boolean): readonly T[] | null {
  try {
    return safeArrayCopy(reflectApply(arrayFilter, array, [callback]) as T[]);
  } catch {
    return null;
  }
}

export function safeOwnDataProperty(value: object, key: PropertyKey): SafeDataProperty {
  try {
    const descriptor = objectGetOwnPropertyDescriptor(value, key);
    if (descriptor === undefined) return { valid: true, present: false };
    if (!reflectApply(objectHasOwnProperty, descriptor, ["value"])) return { valid: false, present: true };
    return { valid: true, present: true, value: descriptor.value };
  } catch {
    return { valid: false, present: false };
  }
}

export function safeGetPrototypeOf(value: object): object | null | undefined {
  try {
    return objectGetPrototypeOf(value);
  } catch {
    return undefined;
  }
}

export function safeOwnDataEntries(
  value: unknown,
  maximum = 100_000,
): readonly (readonly [string, unknown])[] | null {
  if (value === null || (typeof value !== "object" && typeof value !== "function")) return null;
  try {
    const object = value as object;
    const names = objectGetOwnPropertyNames(object);
    const symbols = objectGetOwnPropertySymbols(object);
    if (symbols.length !== 0 || names.length > maximum) return null;
    const entries = new arrayConstructor<readonly [string, unknown]>();
    for (let index = 0; index < names.length; index += 1) {
      const name = names[index];
      if (name === undefined) return null;
      const property = safeOwnDataProperty(object, name);
      if (!property.valid || !property.present) return null;
      const pair = new arrayConstructor<unknown>(2) as unknown as [string, unknown];
      if (!safeDefineArrayValue(pair, 0, name) || !safeDefineArrayValue(pair, 1, property.value)) return null;
      if (!safeDefineArrayValue(entries, index, objectFreeze(pair))) return null;
    }
    return objectFreeze(entries);
  } catch {
    return null;
  }
}

export function safeOwnDataKeys(value: unknown, maximum = 100_000): readonly string[] | null {
  const entries = safeOwnDataEntries(value, maximum);
  if (entries === null) return null;
  const result = new arrayConstructor<string>(entries.length);
  for (let index = 0; index < entries.length; index += 1) {
    const entry = entries[index];
    if (entry === undefined || !safeDefineArrayValue(result, index, entry[0])) return null;
  }
  return objectFreeze(result);
}

export function safeCreateRecord(): Record<string, unknown> {
  return objectCreate(null) as Record<string, unknown>;
}

export function safeDefineData(target: object, key: PropertyKey, value: unknown): boolean {
  try {
    objectDefineProperty(target, key, {
      configurable: false,
      enumerable: true,
      writable: false,
      value,
    });
    return true;
  } catch {
    return false;
  }
}

export function safeDefineHiddenData(target: object, key: PropertyKey, value: unknown): boolean {
  try {
    objectDefineProperty(target, key, {
      configurable: false,
      enumerable: false,
      writable: false,
      value,
    });
    return true;
  } catch {
    return false;
  }
}

export function safeDefineArrayValue<T>(target: T[], index: number, value: T): boolean {
  if (!safeNumberIsSafeInteger(index) || index < 0 || index > 100_000) return false;
  return safeDefineData(target, `${index}`, value);
}

export function safeArrayCopy<T>(value: readonly T[], maximum = 100_000): readonly T[] {
  try {
    const length = value.length;
    if (!safeNumberIsSafeInteger(length) || length < 0 || length > maximum) return objectFreeze(new arrayConstructor<T>());
    const copy = new arrayConstructor<T>(length);
    for (let index = 0; index < length; index += 1) {
      const property = safeOwnDataProperty(value as object, `${index}`);
      if (!property.valid || !property.present || !safeDefineArrayValue(copy, index, property.value as T)) {
        return objectFreeze(new arrayConstructor<T>());
      }
    }
    return objectFreeze(copy);
  } catch {
    return objectFreeze(new arrayConstructor<T>());
  }
}

export function safeFreeze<T>(value: T): Readonly<T> {
  return objectFreeze(value);
}

export function safeSetPrototypeOf<T extends object>(value: T, prototype: object | null): T | null {
  try {
    return objectSetPrototypeOf(value, prototype);
  } catch {
    return null;
  }
}

export const safeUint8Array = typedArrayConstructor;
export function safeUint8ArrayFrom<T extends ArrayLike<number> | Iterable<number>>(value: T): Uint8Array {
  return reflectApply(typedArrayFrom, typedArrayConstructor, [value]) as Uint8Array;
}
