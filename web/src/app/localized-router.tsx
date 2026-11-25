import { useEffect, useState } from "react"
import { RouterProvider } from "react-router"
import { onLocaleChange } from "@/i18n"
import { router } from "./router"

/** Remounts the routed tree when the language changes, so every `t()` call renders again. */
export function LocalizedRouter() {
  const [version, setVersion] = useState(0)
  useEffect(() => onLocaleChange(() => setVersion((v) => v + 1)), [])
  return <RouterProvider key={version} router={router} />
}
