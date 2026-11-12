import { Bug, FileCode2, Radio, SquareTerminal, Download, type LucideIcon } from "lucide-react"
import { Link } from "react-router"
import {
  orderChain,
  shortHash,
  type ChainNode,
  type ChainNodeKind,
  type SampleChain,
  webKindLabel,
} from "@/lib/samples"
import { cn } from "@/lib/utils"

const ICON: Record<ChainNodeKind, LucideIcon> = {
  session: SquareTerminal,
  url: Download,
  sample: FileCode2,
  c2: Radio,
}

const KIND_LABEL: Record<ChainNodeKind, string> = {
  session: "Session",
  url: "Download URL",
  sample: "File",
  c2: "Command server",
}

function NodeLabel({ node, current }: { node: ChainNode; current: string }) {
  const cls = "font-mono text-xs break-all text-fg underline-offset-4 hover:underline"
  if (node.kind === "session" && node.session_id)
    return (
      <Link to={`/attacks/${encodeURIComponent(node.session_id)}`} className={cls}>
        {node.label}
      </Link>
    )
  if (node.kind === "sample" && node.sha256) {
    if (node.sha256 === current)
      return (
        <span className="font-mono text-xs text-fg" aria-current="step">
          {shortHash(node.sha256)}… (this file)
        </span>
      )
    return (
      <Link to={`/malware/samples/${node.sha256}`} className={cls}>
        {shortHash(node.sha256)}…
      </Link>
    )
  }
  if (node.kind === "url")
    return (
      <Link to={`/malware?url=${encodeURIComponent(node.label)}`} className={cls}>
        {node.label}
      </Link>
    )
  return (
    <Link to={`/infrastructure?q=${encodeURIComponent(node.label)}`} className={cls}>
      {node.label}
    </Link>
  )
}

/**
 * The chain as a vertical step list (session, script, binary, command server), in the same
 * shape as the campaign story steps. URLs are shown as text that opens the filtered view.
 */
export function ChainSteps({ chain, current }: { chain: SampleChain; current: string }) {
  const nodes = orderChain(chain)
  return (
    <ol className="relative space-y-4" aria-label="Steps of the chain">
      {nodes.map((n, i) => {
        // The API names a sample node by its family, else by its file kind ("html").
        const web = n.kind === "sample" ? webKindLabel(n.family) : null
        const Icon = n.kind === "sample" && n.family && !web ? Bug : ICON[n.kind]
        const last = i === nodes.length - 1
        return (
          <li
            key={n.id}
            style={{ animationDelay: `${i * 60}ms` }}
            className="relative grid animate-slide-in grid-cols-[2rem_minmax(0,1fr)] gap-x-3"
          >
            {!last ? (
              <span
                aria-hidden
                className="absolute top-8 bottom-[-1rem] left-4 w-px -translate-x-1/2 bg-border-strong"
              />
            ) : null}
            <span
              aria-hidden
              className={cn(
                "relative z-10 flex size-8 items-center justify-center rounded-full border bg-surface-raised text-fg-muted shadow-sm",
              )}
            >
              <Icon className="size-4" strokeWidth={1.75} />
            </span>
            <div className="min-w-0 space-y-0.5 pt-0.5">
              <p className="text-sm font-medium text-fg">
                <span className="mr-1.5 text-xs text-fg-subtle tabular-nums">{i + 1}.</span>
                {KIND_LABEL[n.kind]}
                {n.kind === "sample" && n.family ? (
                  <span className="ml-2 font-normal text-fg-muted">{web ?? n.family}</span>
                ) : null}
              </p>
              <NodeLabel node={n} current={current} />
            </div>
          </li>
        )
      })}
    </ol>
  )
}
