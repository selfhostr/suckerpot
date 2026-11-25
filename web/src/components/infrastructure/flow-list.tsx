import { OctagonAlert } from "lucide-react"
import { BarFill } from "@/components/bar-fill"
import { useMemo } from "react"
import { useIpMask } from "@/app/ip-mask"
import { formatNumber, plural } from "@/lib/format"
import { maskDefanged, type InfrastructureGraph } from "@/lib/infrastructure"

const LIMIT = 8

/**
 * The same story as the flow diagram, as a short list for narrow screens: the indicators used by
 * the most addresses, each with the malware family it points to.
 */
export function FlowList({
  graph,
  onOpenIndicator,
}: {
  graph: InfrastructureGraph
  onOpenIndicator: (id: number) => void
}) {
  const { masked } = useIpMask()
  const rows = useMemo(() => {
    const family = new Map<string, string>()
    const names = new Map(
      graph.nodes.filter((n) => n.kind === "family").map((n) => [n.id, n.label]),
    )
    for (const e of graph.edges)
      if (e.target.startsWith("f:")) family.set(e.source, names.get(e.target) ?? "")
    return graph.nodes
      .filter((n) => n.kind === "indicator")
      .sort((a, b) => b.weight - a.weight || a.id.localeCompare(b.id))
      .slice(0, LIMIT)
      .map((n) => ({ node: n, family: family.get(n.id) ?? null }))
  }, [graph])
  const max = Math.max(1, ...rows.map((r) => r.node.weight))

  return (
    <ul aria-label="Indicators used by the most addresses" className="-mx-4 divide-y border-y">
      {rows.map(({ node, family }) => {
        const label = masked ? maskDefanged(node.label) : node.label
        return (
          <li key={node.id}>
            <button
              type="button"
              onClick={() => node.indicator_id != null && onOpenIndicator(node.indicator_id)}
              className="flex w-full flex-col gap-1.5 px-4 py-3 text-left transition-colors duration-150 hover:bg-surface-hover/50"
            >
              <span className="flex items-center gap-2">
                {node.known ? (
                  <OctagonAlert aria-hidden className="size-3.5 shrink-0 text-sev-severe" />
                ) : null}
                <span className="min-w-0 flex-1 truncate font-mono text-xs text-fg">{label}</span>
                {node.known ? <span className="sr-only">Known malicious</span> : null}
              </span>
              <span className="flex items-center gap-3 text-xs text-fg-muted">
                <span
                  aria-hidden
                  className="h-1.5 flex-1 overflow-hidden rounded-full bg-surface-hover"
                >
                  <BarFill ratio={Math.max(0.06, node.weight / max)} className="bg-fg-muted" />
                </span>
                <span className="text-fg tabular-nums">
                  {formatNumber(node.weight)}{" "}
                  <span className="text-fg-muted">
                    {plural(node.weight, "address", "addresses").replace(/^[\d,]+ /, "")}
                  </span>
                </span>
              </span>
              {family ? <span className="text-xs text-fg-muted">{family}</span> : null}
            </button>
          </li>
        )
      })}
    </ul>
  )
}
