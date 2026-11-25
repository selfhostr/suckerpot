import { t } from "@/i18n"

/**
 * Copy of `base` where the listed properties are getters that translate their key on every read,
 * so a label table built once at module load still follows the active language. The keys are
 * `tk("...")` values; the getters run at render time, never at module scope.
 */
export function withText<T extends object>(base: T, keys: { [K in keyof T]?: string }): T {
  const out = { ...base }
  for (const [prop, key] of Object.entries(keys)) {
    Object.defineProperty(out, prop, {
      get: () => t(key as string),
      enumerable: true,
      configurable: true,
    })
  }
  return out
}

/** A record whose values are translated on read: `{ surge: <tk key>, ... }` -> `{ surge: "Surge" }`. */
export function lazyLabels<K extends string>(keys: Record<K, string>): Record<K, string> {
  const out = {} as Record<K, string>
  for (const k of Object.keys(keys) as K[]) {
    Object.defineProperty(out, k, {
      get: () => t(keys[k]),
      enumerable: true,
      configurable: true,
    })
  }
  return out
}
