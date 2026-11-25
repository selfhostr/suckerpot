import { CardHelp } from "@/components/page-help"
import { useQuery } from "@tanstack/react-query"
import {
  Bell,
  ChevronRight,
  CircleCheck,
  ClipboardPaste,
  Flag,
  Radar,
  ShieldAlert,
  Sparkles,
  type LucideIcon,
} from "lucide-react"
import { Link } from "react-router"
import { useIpMask } from "@/app/ip-mask"
import { ALERTS_SETTINGS } from "@/app/nav"
import { Card } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import { t } from "@/i18n"
import { alertKeys, alertsApi } from "@/lib/alerts"
import { maskIpsInText } from "@/lib/format"
import {
  CARD_TITLE,
  alertsSentence,
  pickTodo,
  type TodayCardData,
  type TodayCardId,
} from "@/lib/today"
import { cn } from "@/lib/utils"

const ICON: Partial<Record<TodayCardId, LucideIcon>> = {
  forms: ClipboardPaste,
  act: ShieldAlert,
  campaigns: Flag,
  new_week: Sparkles,
  exposure: Radar,
}

function TodoRow({ card }: { card: TodayCardData }) {
  const { masked } = useIpMask()
  const Icon = ICON[card.id] ?? Sparkles
  // Servers that hand out malware are the one severe thing on this page: the only red here.
  const urgent = card.id === "act" && !card.empty
  const title = t(CARD_TITLE[card.id])
  const sentence = masked ? maskIpsInText(card.sentence) : card.sentence
  return (
    <li data-todo={card.id}>
      <Link
        to={card.action.to}
        aria-label={t("today_todo_row_aria", { title, sentence, action: card.action.label })}
        className="group -mx-2 flex items-start gap-3 rounded-md px-2 py-2 transition-colors duration-150 hover:bg-surface-hover/70"
      >
        <Icon
          aria-hidden
          className={cn(
            "mt-0.5 size-4 shrink-0",
            urgent ? "text-sev-severe" : card.empty ? "text-fg-subtle" : "text-fg-muted",
          )}
          strokeWidth={1.85}
        />
        <p
          className={cn(
            "line-clamp-2 min-w-0 flex-1 text-sm text-pretty",
            card.empty ? "text-fg-muted" : "text-fg",
          )}
        >
          <span className="font-medium">{t("today_todo_row_title", { title })}</span>{" "}
          <span className={card.empty ? undefined : "text-fg-muted"}>{sentence}</span>
        </p>
        <ChevronRight
          aria-hidden
          className="mt-0.5 size-4 shrink-0 text-fg-subtle transition-colors duration-150 group-hover:text-fg"
        />
      </Link>
    </li>
  )
}

/**
 * One line for the alerts sent lately, under the to-do items. It links to the alerts, where the
 * rules and the outbox are. Hidden when the outbox cannot be read (a viewer, or alerts off).
 */
function AlertsLine() {
  const query = useQuery({
    queryKey: alertKeys.outbox,
    queryFn: () => alertsApi.outbox(),
    refetchInterval: 120_000,
  })
  const { masked } = useIpMask()
  if (!query.data) return null
  const sentence = alertsSentence(query.data.items)
  const text = masked ? maskIpsInText(sentence) : sentence
  return (
    <Link
      to={ALERTS_SETTINGS}
      data-alerts
      aria-label={t("today_alerts_aria", { text })}
      className="group -mx-2 mt-auto flex items-center gap-3 rounded-md border-t px-2 pt-3 pb-1 transition-colors duration-150 hover:text-fg"
    >
      <Bell aria-hidden className="size-4 shrink-0 text-fg-subtle" strokeWidth={1.85} />
      <p className="min-w-0 flex-1 truncate text-sm text-fg-muted">
        <span className="font-medium text-fg">{t("today_alerts_label")}</span> {text}
      </p>
      <ChevronRight
        aria-hidden
        className="size-4 shrink-0 text-fg-subtle transition-colors duration-150 group-hover:text-fg"
      />
    </Link>
  )
}

interface TodoListProps {
  /** Cards from GET /today; undefined while loading. */
  cards: readonly TodayCardData[] | undefined
  error?: boolean
  className?: string
}

/**
 * What needs the operator now, in one small card: the three most pressing items of GET /today
 * (form reports waiting, servers to block, new campaigns, then what is new and your exposure),
 * each one sentence that opens the page where it is handled; then one line for the alerts sent.
 */
export function TodoList({ cards, error = false, className }: TodoListProps) {
  const todo = cards ? pickTodo(cards) : []
  const calm = !!cards && todo.every((c) => c.empty)
  return (
    <Card
      role="region"
      aria-labelledby="todo-title"
      className={cn("min-h-0 overflow-hidden px-4 py-4 sm:px-5 sm:py-5", className)}
    >
      <div className="-my-0.5 flex items-center gap-1">
        <h2 id="todo-title" className="type-eyebrow text-fg-muted">
          {t("today_todo_title")}
        </h2>
        <CardHelp id="todo" />
      </div>
      {error ? (
        <p className="mt-2 text-sm text-fg-muted">{t("today_todo_error")}</p>
      ) : !cards ? (
        <div role="status" aria-label={t("common_loading")} className="mt-3 space-y-3">
          {Array.from({ length: 3 }, (_, i) => (
            <Skeleton key={i} className="h-9 w-full" />
          ))}
        </div>
      ) : (
        <>
          {calm ? (
            <p className="mt-2 flex items-center gap-2 text-sm text-fg">
              <CircleCheck aria-hidden className="size-4 text-fg-muted" strokeWidth={1.85} />
              {t("today_todo_calm")}
            </p>
          ) : null}
          <ul aria-label={t("today_todo_title")} className="mt-1.5">
            {(calm ? todo.slice(0, 2) : todo).map((card) => (
              <TodoRow key={card.id} card={card} />
            ))}
          </ul>
          <AlertsLine />
        </>
      )}
    </Card>
  )
}
