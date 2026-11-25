import { Download, Share2 } from "lucide-react"
import { useId, useState } from "react"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import {
  abuseKeys,
  abuseApi,
  DEFAULT_TLP,
  describeAbuseError,
  exportFile,
  guardReason,
  guardReasonsOf,
  TLP_OPTIONS,
  type ExportScope,
  type Tlp,
} from "@/lib/abuse"
import { saveBlob } from "@/lib/samples"
import { useQuery } from "@tanstack/react-query"
import { useAuth } from "@/app/auth"

/**
 * "Export for CERT": STIX 2.1 or MISP JSON of one report or one campaign, with a TLP choice. The
 * files are guarded by the server; a blocked check is explained here in plain words.
 */
export function ExportMenu({
  scope,
  className,
  blockedReason,
}: {
  scope: ExportScope
  className?: string
  /** Why exporting is not possible right now (the identity check blocked the report). */
  blockedReason?: string
}) {
  const { canWrite } = useAuth()
  // The default TLP is a setting only an administrator can read; everyone else gets GREEN.
  const settings = useQuery({
    queryKey: abuseKeys.settings,
    queryFn: abuseApi.settings,
    enabled: canWrite,
  })
  const [chosen, setChosen] = useState<Tlp | null>(null)
  const tlp = chosen ?? settings.data?.default_tlp ?? DEFAULT_TLP
  const [busy, setBusy] = useState(false)
  const [description, setDescription] = useState("")
  const descId = useId()
  const [message, setMessage] = useState<string | null>(null)
  const [mispOpen, setMispOpen] = useState(false)

  async function run(kind: "stix" | "misp") {
    if (kind === "misp" && !description.trim()) return
    setMispOpen(false)
    setBusy(true)
    setMessage(null)
    try {
      const { blob, filename } = await exportFile(
        kind,
        scope,
        tlp,
        kind === "misp" ? description.trim() : undefined,
      )
      saveBlob(blob, filename ?? `indicators.${kind}.json`)
    } catch (e) {
      const reasons = guardReasonsOf(e)
      setMessage(
        reasons
          ? `Blocked by the identity check. ${reasons.map(guardReason).join(" ")}`
          : describeAbuseError(e),
      )
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className={className}>
      {blockedReason ? (
        <Tooltip>
          <TooltipTrigger asChild>
            <span
              tabIndex={0}
              className="inline-flex rounded-md focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
            >
              <Button variant="outline" size="sm" disabled aria-describedby={descId}>
                <Share2 aria-hidden />
                Export for CERT
              </Button>
            </span>
          </TooltipTrigger>
          <TooltipContent id={descId}>{blockedReason}</TooltipContent>
        </Tooltip>
      ) : (
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="outline" size="sm" disabled={busy}>
              <Share2 aria-hidden />
              {busy ? "Preparing…" : "Export for CERT"}
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-56">
            <DropdownMenuLabel>Sharing level</DropdownMenuLabel>
            <DropdownMenuRadioGroup value={tlp} onValueChange={(v) => setChosen(v as Tlp)}>
              {TLP_OPTIONS.map((o) => (
                <DropdownMenuRadioItem key={o.value} value={o.value}>
                  {o.label}
                </DropdownMenuRadioItem>
              ))}
            </DropdownMenuRadioGroup>
            <DropdownMenuSeparator />
            <DropdownMenuItem onSelect={() => void run("stix")}>
              <Download aria-hidden /> STIX 2.1 bundle
            </DropdownMenuItem>
            <DropdownMenuItem onSelect={() => setMispOpen(true)}>
              <Download aria-hidden /> MISP event (JSON)
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      )}
      <Dialog open={mispOpen} onOpenChange={setMispOpen}>
        <DialogContent>
          <form
            onSubmit={(e) => {
              e.preventDefault()
              void run("misp")
            }}
            className="space-y-4"
          >
            <DialogHeader>
              <DialogTitle>MISP event</DialogTitle>
              <DialogDescription>
                MISP needs a short description of the event. Write it in your own words.
              </DialogDescription>
            </DialogHeader>
            <div className="flex flex-col gap-1">
              <label htmlFor={`${descId}-misp`} className="text-sm font-medium">
                Description
              </label>
              <Input
                id={`${descId}-misp`}
                value={description}
                maxLength={500}
                autoComplete="off"
                onChange={(e) => setDescription(e.target.value)}
              />
            </div>
            <DialogFooter>
              <Button type="submit" disabled={!description.trim()}>
                <Download aria-hidden /> Download
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
      <p
        role="status"
        aria-live="polite"
        className="mt-2 max-w-sm text-xs text-fg-muted empty:hidden"
      >
        {message}
      </p>
    </div>
  )
}
