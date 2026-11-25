import { useMemo, useState } from "react"
import { Link, useNavigate } from "react-router"
import { ResponsiveContainer, Sankey } from "recharts"
import { CountryFlag } from "@/components/country-flag"
import { useMediaQuery } from "@/hooks/use-media-query"
import { formatNumber, plural } from "@/lib/format"
import { sensorMeta } from "@/lib/sensors"
import {
  STAGE_META,
  doorRows,
  isStage,
  linkHref,
  originRows,
  sankeyData,
  type FlowNode,
  type StoryResponse,
} from "@/lib/story"

// recharts does not export the props it hands to a custom Sankey node or link.
interface NodeProps {
  x: number
  y: number
  width: number
  height: number
  index: number
  payload: unknown
}
interface LinkProps {
  sourceX: number
  targetX: number
  sourceY: number
  targetY: number
  sourceControlX: number
  targetControlX: number
  linkWidth: number
  index: number
  payload: { source: unknown; target: unknown }
}

type Hover = { kind: "node"; id: string } | { kind: "link"; source: string; target: string } | null

function nodeColor(node: FlowNode): string {
  if (node.column === "stage")
    return isStage(node.key) ? STAGE_META[node.key].cssVar : "var(--sev-info)"
  if (node.column === "door") return sensorMeta(node.key)?.shadeVar ?? "var(--fg-subtle)"
  return "var(--fg-subtle)"
}

/** The part of a Sankey payload we care about (recharts spreads our node fields into it). */
function asFlowNode(payload: unknown): FlowNode | null {
  const p = payload as Partial<FlowNode> | undefined
  return p && typeof p.id === "string" && typeof p.href === "string" ? (p as FlowNode) : null
}

const MIN_NODE = 6
const MIN_LABEL_GAP = 14

/**
 * Keeps labels of one column MIN_LABEL_GAP apart. recharts draws the nodes of a column top to
 * bottom, so each label only has to clear the one before it. One nudger lives for one pass.
 */
function labelNudger() {
  const last = new Map<string, number>()
  return (column: string, ideal: number): number => {
    const y = Math.max(ideal, (last.get(column) ?? -Infinity) + MIN_LABEL_GAP)
    last.set(column, y)
    return y
  }
}

const COLUMN_TITLES = ["Where they come from", "Which door they knock on", "How far they got"]

interface FlowProps {
  flow: StoryResponse["flow"]
}

/** Desktop: an animated Sankey. Narrow screens get {@link FlowList} instead. */
function FlowSankey({ flow }: FlowProps) {
  const navigate = useNavigate()
  const data = useMemo(() => sankeyData(flow), [flow])
  const [hover, setHover] = useState<Hover>(null)

  const byId = useMemo(() => new Map(data.nodes.map((n) => [n.id, n])), [data])
  const caption = (() => {
    if (!hover)
      return "Hover over a block or a ribbon for the numbers. Click one to see those visits."
    if (hover.kind === "node") {
      const n = byId.get(hover.id)
      return n ? `${n.label}: ${plural(n.sessions, "visit")}` : ""
    }
    const s = byId.get(hover.source)
    const t = byId.get(hover.target)
    const l = data.links.find(
      (x) => data.nodes[x.source]?.id === hover.source && data.nodes[x.target]?.id === hover.target,
    )
    return s && t && l ? `${s.label} to ${t.label}: ${plural(l.value, "visit")}` : ""
  })()

  const touches = (id: string) =>
    hover === null ||
    (hover.kind === "node" ? hover.id === id : hover.source === id || hover.target === id)

  const nudge = labelNudger()
  const renderNode = (props: NodeProps) => {
    const node = asFlowNode(props.payload)
    if (!node) return <g />
    const { x, y, width, height, index } = props
    const color = nodeColor(node)
    const open = () => void navigate(node.href)
    const labelled = node.column !== "origin" || height >= 12
    const drawn = Math.max(height, MIN_NODE)
    // Labels of one column are nudged apart so tiny neighbours stay readable.
    const ly = labelled ? nudge(node.column, y + height / 2) : y + height / 2
    const textX = x + width + (node.column === "stage" ? 6 : 8)
    const label = `${node.label}, ${plural(node.sessions, "visit")}`
    return (
      <g
        role="link"
        tabIndex={0}
        aria-label={`${label}. Show these visits.`}
        className="animate-fade-in cursor-pointer outline-none [&:focus-visible>rect]:stroke-fg [&:focus-visible>rect]:stroke-2"
        style={{ animationDelay: `${index * 25}ms` }}
        onClick={open}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault()
            open()
          }
        }}
        onMouseEnter={() => setHover({ kind: "node", id: node.id })}
        onMouseLeave={() => setHover(null)}
        onFocus={() => setHover({ kind: "node", id: node.id })}
        onBlur={() => setHover(null)}
      >
        <title>{label}</title>
        <rect
          x={x}
          y={y}
          width={width}
          height={drawn}
          rx={2}
          fill={color}
          opacity={touches(node.id) ? 1 : 0.4}
        />
        {labelled ? (
          <text
            x={textX}
            y={ly}
            dy="0.35em"
            textAnchor="start"
            className="fill-fg stroke-surface text-xs"
            strokeWidth={3}
            paintOrder="stroke"
          >
            {node.label}
            {node.column !== "origin" ? (
              <tspan className="fill-fg-muted tabular-nums">{` · ${formatNumber(node.sessions)}`}</tspan>
            ) : null}
          </text>
        ) : null}
      </g>
    )
  }

  const renderLink = (props: LinkProps) => {
    const source = asFlowNode(props.payload.source)
    const target = asFlowNode(props.payload.target)
    if (!source || !target) return <g />
    const { sourceX, targetX, sourceY, targetY, sourceControlX, targetControlX, linkWidth, index } =
      props
    const y1 = sourceY + linkWidth / 2
    const y2 = targetY + linkWidth / 2
    const active =
      hover === null ||
      (hover.kind === "link"
        ? hover.source === source.id && hover.target === target.id
        : hover.id === source.id || hover.id === target.id)
    const href = linkHref(source, target)
    const label = `${source.label} to ${target.label}`
    return (
      <path
        role="link"
        tabIndex={-1}
        aria-label={`${label}. Show these visits.`}
        d={`M${sourceX},${y1} C${sourceControlX},${y1} ${targetControlX},${y2} ${targetX},${y2}`}
        fill="none"
        stroke={nodeColor(source.column === "origin" ? source : target)}
        strokeWidth={Math.max(linkWidth, 1)}
        strokeOpacity={active ? 0.4 : 0.1}
        className="animate-fade-in cursor-pointer transition-[stroke-opacity] duration-150"
        style={{ animationDelay: `${200 + index * 20}ms` }}
        onClick={() => void navigate(href)}
        onMouseEnter={() => setHover({ kind: "link", source: source.id, target: target.id })}
        onMouseLeave={() => setHover(null)}
      >
        <title>{label}</title>
      </path>
    )
  }

  return (
    <div>
      <div className="grid grid-cols-3 px-1 text-xs font-medium text-fg-muted" aria-hidden>
        {COLUMN_TITLES.map((t, i) => (
          <span key={t} className={i === 1 ? "text-center" : i === 2 ? "text-right" : undefined}>
            {t}
          </span>
        ))}
      </div>
      <div className="h-[360px] w-full">
        <ResponsiveContainer width="100%" height="100%">
          <Sankey
            data={data}
            node={renderNode}
            link={renderLink}
            nodeWidth={10}
            nodePadding={14}
            sort={false}
            iterations={32}
            margin={{ top: 8, right: 200, bottom: 8, left: 8 }}
          />
        </ResponsiveContainer>
      </div>
      <p className="mt-2 text-xs text-fg-muted tabular-nums" aria-live="polite">
        {caption}
      </p>
    </div>
  )
}

/** Narrow screens: who knocked, then one stacked bar per door showing how far its visitors got. */
function FlowList({ flow }: FlowProps) {
  const doors = useMemo(() => doorRows(flow), [flow])
  const origins = useMemo(() => originRows(flow), [flow])
  const max = Math.max(1, ...doors.map((d) => d.total))
  return (
    <div className="space-y-6">
      <section aria-labelledby="flow-origins">
        <h3 id="flow-origins" className="mb-2 type-eyebrow text-fg-muted">
          {COLUMN_TITLES[0]}
        </h3>
        <ul className="grid grid-cols-1 gap-x-4 sm:grid-cols-2">
          {origins.map((o) => (
            <li key={o.id}>
              <Link
                to={o.href}
                className="flex min-h-11 items-center gap-2 rounded-md px-2 text-sm hover:bg-surface-hover/70"
              >
                {o.key !== "other" ? <CountryFlag code={o.key} decorative /> : null}
                <span className="min-w-0 flex-1 truncate text-fg">{o.label}</span>
                <span className="text-fg-muted tabular-nums">{formatNumber(o.sessions)}</span>
              </Link>
            </li>
          ))}
        </ul>
      </section>
      <section aria-labelledby="flow-doors">
        <h3 id="flow-doors" className="mb-2 type-eyebrow text-fg-muted">
          {COLUMN_TITLES[1]}, and how far they got
        </h3>
        <ul className="space-y-3">
          {doors.map((d) => {
            const meta = sensorMeta(d.node.key)
            const Icon = meta?.icon
            return (
              <li key={d.node.id}>
                <Link
                  to={d.node.href}
                  className="mb-1 flex items-center gap-2 text-sm text-fg hover:underline hover:underline-offset-4"
                >
                  {Icon ? <Icon aria-hidden className="size-4 text-fg-muted" /> : null}
                  <span className="flex-1">{d.node.label}</span>
                  <span className="text-fg-muted tabular-nums">{formatNumber(d.total)}</span>
                </Link>
                <div
                  className="flex h-3 gap-px overflow-hidden rounded-sm bg-surface-hover"
                  style={{ width: `${Math.max(8, (d.total / max) * 100)}%` }}
                >
                  {d.segments.map((s) => (
                    <Link
                      key={s.stage}
                      to={s.href}
                      aria-label={`${s.label}: ${plural(s.value, "visit")}`}
                      title={`${s.label}: ${formatNumber(s.value)}`}
                      className="h-full min-w-px"
                      style={{
                        flexGrow: s.value,
                        flexBasis: 0,
                        background: STAGE_META[s.stage].cssVar,
                      }}
                    />
                  ))}
                </div>
              </li>
            )
          })}
        </ul>
      </section>
    </div>
  )
}

/** The funnel from origin to door to stage: a Sankey on wide screens, bars on a phone. */
export function StoryFlow({ flow }: FlowProps) {
  const wide = useMediaQuery("(min-width: 768px)")
  return wide ? <FlowSankey flow={flow} /> : <FlowList flow={flow} />
}
