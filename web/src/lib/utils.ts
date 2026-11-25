import { clsx, type ClassValue } from "clsx"
import { twMerge } from "tailwind-merge"
import { t } from "@/i18n"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

/**
 * An object whose text fields are read through `t()` each time they are used. A data table can
 * then live at module scope and still follow the language: `keys` maps each field to its message
 * key (written with `tk()`), `rest` holds the plain fields.
 */
export function withText<K extends string, R extends object>(
  keys: Record<K, string>,
  rest: R,
): R & Record<K, string> {
  const item = { ...rest }
  for (const field of Object.keys(keys) as K[]) {
    const key = keys[field]
    Object.defineProperty(item, field, { get: () => t(key), enumerable: true })
  }
  return item as R & Record<K, string>
}
