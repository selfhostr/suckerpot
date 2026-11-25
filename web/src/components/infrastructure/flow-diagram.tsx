import { useMemo, useState } from "react"
import { useNavigate } from "react-router"
import { useIpMask } from "@/app/ip-mask"
import { t } from "@/i18n"
import { formatNumber, maskIp } from "@/lib/format"
import {
  buildFlow,
  maskDefanged,
  type FlowNode,
  type GraphEdge,
  type InfrastructureGraph,
} from "@/lib/infrastructure"

const W = 900
const ROW = 30
const PAD = 14
const SRC_X = 170 // source dots; labels end just left of it
const PILL_X = 462 // centre of the indicator pills
const PILL_W = 250
const FAM_X = 712 // family dots; labels start just right of it
const FAM_CHARS = 26

interface Placed<T> {
  node: T
  y: number
}

function place(nodes: readonly FlowNode[], height: number): Placed<FlowNode>[] {
  const used = nodes.length * ROW
  const top = PAD + Math.max(0, (height - 2 * PAD - used) / 2)
  return nodes.map((node, i) => ({ node, y: top + i * ROW + ROW / 2 }))
}

/**
 * Each family sits level with the indicators that point to it (weighted mean), pushed apart just
 * enough to keep one row between labels. Lines to families then run nearly flat.
 */
function placeFamilies(
  fams: readonly FlowNode[],
  edges: readonly GraphEdge[],
  indicatorY: ReadonlyMap<string, number>,
  height: number,
): Placed<FlowNode>[] {
  const lo = PAD + ROW / 2
  const hi = height - PAD - ROW / 2
  const ys = fams.map((f, i) => {
    let sum = 0
    let total = 0
    for (const e of edges) {
      const y = e.target === f.id ? indicatorY.get(e.source) : undefined
      if (y === undefined) continue
      sum += y * e.weight
      total += e.weight
    }
    return total > 0 ? sum / total : lo + i * ROW
  })
  for (let i = 0; i < ys.length; i++)
    ys[i] = Math.max(ys[i] ?? lo, i > 0 ? (ys[i - 1] ?? lo) + ROW : lo)
  for (let i = ys.length - 1; i >= 0; i--)
    ys[i] = Math.min(ys[i] ?? hi, i < ys.length - 1 ? (ys[i + 1] ?? hi) - ROW : hi)
  return fams.map((node, i) => ({ node, y: ys[i] ?? lo }))
}

/** Everything on the paths through `id`: upstream and downstream, never sideways. */
function traced(id: string, edges: readonly GraphEdge[]): Set<string> {
  const out = new Set([id])
  const kind = id.slice(0, 2)
  const next = (from: string, dir: "down" | "up") =>
    edges.flatMap((e) =>
      dir === "down" ? (e.source === from ? [e.target] : []) : e.target === from ? [e.source] : [],
    )
  if (kind === "s:") {
    for (const i of next(id, "down")) {
      out.add(i)
      for (const f of next(i, "down")) out.add(f)
    }
  } else if (kind === "f:") {
    for (const i of next(id, "up")) {
      out.add(i)
      for (const s of next(i, "up")) out.add(s)
    }
  } else {
    for (const n of [...next(id, "up"), ...next(id, "down")]) out.add(n)
  }
  return out
}

/** The "severe" octagon, as in the threat-intelligence badge. */
function octagon(cx: number, cy: number, r: number): string {
  return Array.from({ length: 8 }, (_, i) => {
    const a = (Math.PI / 4) * i + Math.PI / 8
    return `${(cx + r * Math.cos(a)).toFixed(2)},${(cy + r * Math.sin(a)).toFixed(2)}`
  }).join(" ")
}

function curve(x1: number, y1: number, x2: number, y2: number): string {
  const mid = (x1 + x2) / 2
  return `M${x1},${y1} C${mid},${y1} ${mid},${y2} ${x2},${y2}`
}

const shorten = (s: string, n: number) => (s.length > n ? `${s.slice(0, n - 1)}…` : s)

interface FlowDiagramProps {
  graph: InfrastructureGraph
  onOpenIndicator: (id: number) => void
}

/**
 * Source addresses on the left, the indicators they used in the middle, the malware families on
 * the right. Plain SVG: no graph library. Indicators are buttons that open the detail panel;
 * addresses open their profile. Nothing in it is a link to an indicator host.
 */
export function FlowDiagram({ graph, onOpenIndicator }: FlowDiagramProps) {
  const flow = useMemo(() => buildFlow(graph), [graph])
  const navigate = useNavigate()
  const { masked } = useIpMask()
  const [active, setActive] = useState<string | null>(null)

  const rows = Math.max(flow.sources.length, flow.indicators.length, flow.families.length, 1)
  const height = rows * ROW + 2 * PAD
  const src = place(flow.sources, height)
  const ind = place(flow.indicators, height)
  const fam = placeFamilies(
    flow.families,
    flow.edges,
    new Map(ind.map((p) => [p.node.id, p.y])),
    height,
  )
  const pos = new Map<string, { x: number; y: number }>()
  for (const { node, y } of src) pos.set(node.id, { x: SRC_X, y })
  for (const { node, y } of ind) pos.set(node.id, { x: PILL_X, y })
  for (const { node, y } of fam) pos.set(node.id, { x: FAM_X, y })

  const maxWeight = Math.max(1, ...flow.edges.map((e) => e.weight))
  const connected = active ? traced(active, flow.edges) : new Set<string>()
  const edgeOn = (a: string, b: string) => connected.has(a) && connected.has(b)
  const hover = (id: string) => ({
    onMouseEnter: () => setActive(id),
    onFocus: () => setActive(id),
    onBlur: () => setActive(null),
  })

  const hiddenCase =
    flow.hidden.indicators > 0 && flow.hidden.families > 0
      ? "both"
      : flow.hidden.indicators > 0
        ? "indicators"
        : flow.hidden.families > 0
          ? "families"
          : "none"

  return (
    <figure className="m-0">
      <svg
        viewBox={`0 0 ${W} ${height}`}
        role="group"
        aria-label={t("infra_flow_label", {
          sources: flow.sources.length,
          indicators: flow.indicators.length,
          families: flow.families.length,
        })}
        className="h-auto w-full"
        onMouseLeave={() => setActive(null)}
      >
        <g fill="none" aria-hidden>
          {flow.edges.map((e) => {
            const a = pos.get(e.source)
            const b = pos.get(e.target)
            if (!a || !b) return null
            const isFamily = e.target.startsWith("f:")
            const x1 = isFamily ? PILL_X + PILL_W / 2 : a.x + 5
            const x2 = isFamily ? b.x - 5 : PILL_X - PILL_W / 2
            const on = edgeOn(e.source, e.target)
            return (
              <path
                key={`${e.source}>${e.target}`}
                d={curve(x1, a.y, x2, b.y)}
                stroke={on ? "var(--fg-muted)" : "var(--border-strong)"}
                strokeOpacity={active && !on ? 0.2 : on ? 1 : 0.7}
                strokeWidth={0.8 + 2.4 * (e.weight / maxWeight)}
                style={{ transition: "stroke-opacity 150ms, stroke 150ms" }}
              />
            )
          })}
        </g>

        {src.map(({ node, y }) => (
          <SourceNode
            key={node.id}
            node={node}
            y={y}
            masked={masked}
            dim={active !== null && !connected.has(node.id)}
            hover={hover(node.id)}
            onOpen={() => void navigate(`/attackers/${encodeURIComponent(node.label)}`)}
          />
        ))}

        {ind.map(({ node, y }) => {
          const label = masked ? maskDefanged(node.label) : node.label
          const known = node.known === true
          const dim = active !== null && !connected.has(node.id)
          return (
            <g
              key={node.id}
              role="button"
              tabIndex={0}
              aria-label={t("infra_flow_indicator_label", {
                label,
                count: node.weight,
                known: known ? "yes" : "no",
              })}
              onClick={() => node.indicator_id != null && onOpenIndicator(node.indicator_id)}
              onKeyDown={(ev) => {
                if ((ev.key === "Enter" || ev.key === " ") && node.indicator_id != null) {
                  ev.preventDefault()
                  onOpenIndicator(node.indicator_id)
                }
              }}
              {...hover(node.id)}
              className="cursor-pointer outline-none [&:focus-visible>rect]:stroke-[var(--ring)] [&:focus-visible>rect]:stroke-2"
              opacity={dim ? 0.35 : 1}
              style={{ transition: "opacity 150ms" }}
            >
              <title>{t("infra_flow_indicator_title", { label })}</title>
              <rect
                x={PILL_X - PILL_W / 2}
                y={y - 12}
                width={PILL_W}
                height={24}
                rx={6}
                fill="var(--surface-raised)"
                stroke={known ? "var(--sev-severe)" : "var(--border-strong)"}
                strokeOpacity={known ? 0.6 : 1}
              />
              {known ? (
                <polygon
                  points={octagon(PILL_X - PILL_W / 2 + 12, y, 5)}
                  fill="var(--sev-severe)"
                />
              ) : (
                <circle
                  cx={PILL_X - PILL_W / 2 + 12}
                  cy={y}
                  r={3.5}
                  fill="none"
                  stroke="var(--fg-subtle)"
                  strokeWidth={1.5}
                />
              )}
              <text
                x={PILL_X - PILL_W / 2 + 26}
                y={y + 4}
                fontSize={11.5}
                fill="var(--fg)"
                fontFamily="var(--font-mono)"
              >
                {shorten(label, 30)}
              </text>
              <text
                x={PILL_X + PILL_W / 2 - 10}
                y={y + 4}
                fontSize={11}
                textAnchor="end"
                fill="var(--fg-muted)"
                style={{ fontVariantNumeric: "tabular-nums" }}
              >
                {formatNumber(node.weight)}
              </text>
            </g>
          )
        })}

        {fam.map(({ node, y }) => (
          <g
            key={node.id}
            role="link"
            tabIndex={0}
            aria-label={t("infra_family_show", { name: node.label })}
            onClick={() =>
              void navigate(`/infrastructure?family=${encodeURIComponent(node.label)}`)
            }
            onKeyDown={(ev) => {
              if (ev.key === "Enter")
                void navigate(`/infrastructure?family=${encodeURIComponent(node.label)}`)
            }}
            {...hover(node.id)}
            className="cursor-pointer outline-none [&:focus-visible>text]:underline [&:hover>text]:underline"
            opacity={active !== null && !connected.has(node.id) ? 0.35 : 1}
            style={{ transition: "opacity 150ms" }}
          >
            <title>{t("infra_flow_family_title", { name: node.label })}</title>
            <rect x={FAM_X - 8} y={y - 12} width={W - FAM_X + 8} height={24} fill="transparent" />
            <circle cx={FAM_X} cy={y} r={4} fill="var(--fg-muted)" />
            <text x={FAM_X + 12} y={y + 4} fontSize={12} fill="var(--fg)">
              {shorten(node.label, FAM_CHARS)}
            </text>
          </g>
        ))}

        <g
          fontSize={10.5}
          fill="var(--fg-subtle)"
          fontWeight={500}
          letterSpacing="0.06em"
          style={{ textTransform: "uppercase" }}
        >
          <text x={SRC_X + 5} y={10} textAnchor="end">
            <title>{t("infra_flow_head_sources")}</title>
            {shorten(t("infra_flow_head_sources"), 22)}
          </text>
          <text x={PILL_X} y={10} textAnchor="middle">
            <title>{t("infra_flow_head_indicators")}</title>
            {shorten(t("infra_flow_head_indicators"), 34)}
          </text>
          <text x={FAM_X - 4} y={10}>
            <title>{t("infra_flow_head_families")}</title>
            {shorten(t("infra_flow_head_families"), 26)}
          </text>
        </g>
      </svg>
      <figcaption className="mt-3 text-xs text-fg-muted">
        {t("infra_flow_caption")}
        {flow.hidden.sources > 0
          ? ` ${t("infra_flow_folded", { count: flow.hidden.sources })}`
          : ""}
        {hiddenCase !== "none"
          ? ` ${t("infra_flow_hidden", {
              which: hiddenCase,
              indicators: flow.hidden.indicators,
              families: flow.hidden.families,
            })}`
          : ""}
        {graph.truncated ? ` ${t("infra_flow_capped")}` : ""}
      </figcaption>
    </figure>
  )
}

function SourceNode({
  node,
  y,
  masked,
  dim,
  hover,
  onOpen,
}: {
  node: FlowNode
  y: number
  masked: boolean
  dim: boolean
  hover: Pick<React.SVGProps<SVGGElement>, "onMouseEnter" | "onFocus" | "onBlur">
  onOpen: () => void
}) {
  const folded = node.folded !== undefined
  const label = folded ? node.label : masked ? maskIp(node.label) : node.label
  return (
    <g
      opacity={dim ? 0.35 : 1}
      style={{ transition: "opacity 150ms" }}
      {...hover}
      {...(folded
        ? {}
        : {
            role: "link",
            tabIndex: 0,
            "aria-label": t("infra_flow_source_label", { label }),
            onClick: onOpen,
            onKeyDown: (ev: React.KeyboardEvent) => {
              if (ev.key === "Enter") onOpen()
            },
            className:
              "cursor-pointer outline-none [&:focus-visible>rect]:stroke-[var(--ring)] [&:focus-visible>rect]:stroke-2",
          })}
    >
      <title>{folded ? label : t("infra_flow_source_title", { label })}</title>
      <rect x={0} y={y - 12} width={SRC_X + 12} height={24} fill="transparent" rx={4} />
      <circle
        cx={SRC_X}
        cy={y}
        r={folded ? 4 : 3.5}
        fill={folded ? "none" : "var(--fg-muted)"}
        stroke="var(--fg-muted)"
        strokeWidth={folded ? 1.5 : 0}
      />
      <text
        x={SRC_X - 12}
        y={y + 4}
        textAnchor="end"
        fontSize={11.5}
        fill={folded ? "var(--fg-muted)" : "var(--fg)"}
        fontFamily={folded ? undefined : "var(--font-mono)"}
      >
        {label}
      </text>
    </g>
  )
}
