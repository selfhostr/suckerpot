import "@xterm/xterm/css/xterm.css"
import { FitAddon } from "@xterm/addon-fit"
import { Terminal } from "@xterm/xterm"
import { Info, Pause, Play, RotateCcw, Wand2 } from "lucide-react"
import { useEffect, useMemo, useReducer, useRef } from "react"
import { t } from "@/i18n"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Slider } from "@/components/ui/slider"
import { SegmentedControl } from "@/components/segmented-control"
import { Toggle } from "@/components/ui/toggle"
import { useReducedMotion } from "@/hooks/use-reduced-motion"
import { cn } from "@/lib/utils"
import { ReplayEngine, SPEEDS, type ReplaySink } from "./engine"
import { buildSteps, formatClockTime, type ReplaySource } from "./frames"
import { TERMINAL_BG, TERMINAL_THEME } from "./terminal-theme"

/** Seconds skipped by the arrow keys. */
const SKIP_SECONDS = 5

function cssVar(name: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim()
}

/** Replays assume an 80-column terminal; narrower screens scroll sideways instead of re-wrapping. */
const MIN_COLS = 80

interface TerminalReplayProps {
  source: ReplaySource
  /** Screenshot mode: hide the last two octets of every IPv4 address in the output. */
  masked: boolean
}

/**
 * Terminal replay of an SSH/Telnet session.
 *
 * Safety contract (see sanitize.ts): the stream is filtered before it is
 * written; the terminal has no input (`disableStdin`), and nothing listens to
 * what the emulator would send back; links are never opened; no clipboard,
 * image or link add-ons are loaded.
 */
export function TerminalReplay({ source, masked }: TerminalReplayProps) {
  const reduced = useReducedMotion()
  const hostRef = useRef<HTMLDivElement>(null)
  const termRef = useRef<Terminal | null>(null)
  const [, rerender] = useReducer((n: number) => n + 1, 0)

  const engine = useMemo(() => {
    const steps = buildSteps(source.frames, { mask: masked })
    const sink: ReplaySink = {
      write: (d) => termRef.current?.write(d),
      reset: () => termRef.current?.reset(),
    }
    return new ReplayEngine(steps, sink)
  }, [source, masked])

  // Create the terminal once.
  useEffect(() => {
    const host = hostRef.current
    if (!host) return
    const term = new Terminal({
      disableStdin: true,
      cursorBlink: false,
      cursorInactiveStyle: "none",
      scrollback: 5000,
      fontSize: window.matchMedia("(max-width: 639px)").matches ? 12 : 13,
      lineHeight: 1.35,
      fontFamily: cssVar("--font-mono"),
      theme: TERMINAL_THEME,
      // Links in attacker output are plain text: never activated, never opened.
      linkHandler: { activate: () => undefined, allowNonHttpProtocols: false },
    })
    const fit = new FitAddon()
    term.loadAddon(fit)
    term.open(host)
    // Defence in depth: even if a sequence slipped past the filter, these are no-ops.
    for (const ident of [0, 1, 2, 8, 52]) term.parser.registerOscHandler(ident, () => true)
    // The emulator's helper textarea would receive focus and keystrokes: keep it out of reach.
    term.textarea?.setAttribute("tabindex", "-1")
    term.textarea?.setAttribute("aria-hidden", "true")
    termRef.current = term

    const doFit = () => {
      try {
        const dims = fit.proposeDimensions()
        if (dims && Number.isFinite(dims.cols) && Number.isFinite(dims.rows)) {
          term.resize(Math.max(MIN_COLS, dims.cols), Math.max(1, dims.rows))
        }
      } catch {
        // Host not measurable yet (hidden or zero-sized): the next resize retries.
      }
    }
    doFit()
    const ro = new ResizeObserver(doFit)
    ro.observe(host)
    // Fit again once the monospace font is in, since cell size depends on it.
    let live = true
    void document.fonts
      .load(`13px ${cssVar("--font-mono").split(",")[0] ?? "monospace"}`)
      .then(() => {
        if (!live) return
        term.options.fontFamily = cssVar("--font-mono")
        doFit()
      })
      .catch(() => undefined)
    return () => {
      live = false
      ro.disconnect()
      termRef.current = null
      term.dispose()
    }
  }, [])

  // Bind the engine: start from a clean screen, autoplay unless motion is reduced.
  useEffect(() => {
    termRef.current?.reset()
    const unsubscribe = engine.subscribe(rerender)
    if (!reduced) engine.play()
    rerender()
    return () => {
      unsubscribe()
      engine.pause()
    }
  }, [engine, reduced])

  // Smooth position while playing.
  const playing = engine.playing
  useEffect(() => {
    if (!playing) return
    let raf = requestAnimationFrame(function tick() {
      rerender()
      raf = requestAnimationFrame(tick)
    })
    return () => cancelAnimationFrame(raf)
  }, [playing, engine])

  const position = engine.position()
  const duration = engine.duration
  const atEnd = engine.ended && !playing

  const onKeyDown = (e: React.KeyboardEvent<HTMLDivElement>) => {
    const target = e.target as HTMLElement
    // Buttons, radios and the slider have their own keyboard behaviour.
    if (target.closest('button, [role="slider"], [role="radio"]')) return
    if (e.key === " ") engine.toggle()
    else if (e.key === "ArrowRight") engine.skip(SKIP_SECONDS)
    else if (e.key === "ArrowLeft") engine.skip(-SKIP_SECONDS)
    else return
    e.preventDefault()
    e.stopPropagation()
  }

  return (
    <div className="space-y-3">
      {source.reconstructed || source.truncated ? (
        <div className="flex flex-wrap items-center gap-2 text-xs text-fg-muted">
          {source.reconstructed ? (
            <Badge variant="outline" className="gap-1.5 font-normal text-fg-muted">
              <Wand2 aria-hidden className="size-3" />
              {t("replay_reconstructed")}
            </Badge>
          ) : null}
          {source.truncated ? (
            <p role="note" className="inline-flex items-center gap-1.5">
              <Info aria-hidden className="size-3.5 shrink-0" />
              {t("replay_truncated")}
            </p>
          ) : null}
        </div>
      ) : null}

      <div
        role="group"
        aria-label={t("replay_group_label")}
        tabIndex={0}
        onKeyDownCapture={onKeyDown}
        className="overflow-x-auto rounded-md border border-[#23252a] p-3 outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50"
        style={{ backgroundColor: TERMINAL_BG, colorScheme: "dark" }}
      >
        <div ref={hostRef} className="h-64 w-full sm:h-80" />
        <p className="sr-only">
          {t("replay_sr_note")}
        </p>
      </div>

      <div className="flex flex-wrap items-center gap-x-4 gap-y-3">
        <div className="flex items-center gap-1.5">
          <Button
            type="button"
            size="icon"
            variant="outline"
            aria-label={playing ? t("replay_pause") : atEnd ? t("replay_replay") : t("replay_play")}
            onClick={() => engine.toggle()}
          >
            {playing ? (
              <Pause aria-hidden />
            ) : atEnd ? (
              <RotateCcw aria-hidden />
            ) : (
              <Play aria-hidden />
            )}
          </Button>
          <Button
            type="button"
            size="icon"
            variant="ghost"
            aria-label={t("replay_restart")}
            onClick={() => engine.restart()}
          >
            <RotateCcw aria-hidden />
          </Button>
        </div>

        <p className="font-mono text-xs text-fg-muted tabular-nums" aria-hidden>
          {formatClockTime(position)} / {formatClockTime(duration)}
        </p>

        <div className="ml-auto flex flex-wrap items-center gap-2">
          <SegmentedControl
            label={t("replay_speed")}
            value={String(engine.speed)}
            onChange={(v) => engine.setSpeed(Number(v))}
            options={SPEEDS.map((s) => ({ value: String(s), label: `${s}×` }))}
          />
          <Toggle
            pressed={engine.skipIdle}
            onPressedChange={(on) => engine.setSkipIdle(on)}
            aria-label={t("replay_skip_idle_label")}
            className={cn(
              "h-8 rounded-md border px-3 text-xs font-medium text-fg-muted data-[state=on]:border-border-strong data-[state=on]:bg-surface-raised data-[state=on]:text-fg",
            )}
          >
            {t("replay_skip_idle")}
          </Toggle>
        </div>

        <Slider
          className="basis-full py-1.5"
          min={0}
          max={Math.max(duration, 0.1)}
          step={0.05}
          value={[Math.min(position, Math.max(duration, 0.1))]}
          onValueChange={([v]) => {
            if (v !== undefined) engine.seek(v)
          }}
          thumbLabel={t("replay_position")}
          thumbValueText={t("replay_position_value", {
            position: formatClockTime(position),
            duration: formatClockTime(duration),
          })}
        />
      </div>
    </div>
  )
}
