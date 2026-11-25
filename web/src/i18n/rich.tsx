import { Fragment, type ReactNode } from "react"
import { t, type MessageValues } from "./index"

/**
 * A sentence with React nodes inside it (a code span, a link, bold text). The message holds a
 * `{name}` placeholder where the node goes, so no markup lives in the string files:
 *
 *   "Run {command} on the sensor." -> tNodes("setup_run", {}, { command: <code>make up</code> })
 */
export function tNodes(
  key: string,
  values: MessageValues = {},
  nodes: Record<string, ReactNode> = {},
): ReactNode {
  const marks: MessageValues = { ...values }
  for (const name of Object.keys(nodes)) marks[name] = `\u0001${name}\u0001`
  const text = t(key, marks)
  if (!text.includes("\u0001")) return text
  const parts = text.split("\u0001")
  return parts.map((part, i) =>
    i % 2 === 1 ? <Fragment key={i}>{nodes[part]}</Fragment> : part === "" ? null : part,
  )
}
