import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { useId, useState } from "react"
import { Field } from "@/components/form-parts"
import { FindingCard } from "@/components/finding-card"
import { SkeletonText } from "@/components/skeletons"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Switch } from "@/components/ui/switch"
import {
  abuseKeys,
  describeAbuseError,
  digestApi,
  digestKeys,
  localToUtcMinute,
  utcMinuteToLocal,
  type DigestSettings,
} from "@/lib/abuse"
import { browserTimeZone } from "@/lib/format"

export const DIGEST_EXPLANATION =
  "A provider gets at most one mail a day, at this hour, with all its sources. A digest holds at most 100 sources: the rest goes in a second part 2 hours later, at most 3 parts a day. The daily limit counts mails, not sources."

function DigestForm({ initial }: { initial: DigestSettings }) {
  const qc = useQueryClient()
  const ids = { on: useId(), hour: useId() }
  const [enabled, setEnabled] = useState(initial.enabled)
  const [hour, setHour] = useState(initial.minute === null ? "" : utcMinuteToLocal(initial.minute))
  const [error, setError] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)
  const noSmtp = initial.minute === null
  const save = useMutation({
    mutationFn: (body: { enabled: boolean; minute?: number }) => digestApi.save(body),
    onSuccess: (d) => {
      setError(null)
      setSaved(true)
      qc.setQueryData(digestKeys.digest, d)
      void qc.invalidateQueries({ queryKey: abuseKeys.all })
    },
    onError: (e) => setError(describeAbuseError(e)),
  })

  function submit() {
    setSaved(false)
    if (noSmtp) {
      save.mutate({ enabled })
      return
    }
    const minute = localToUtcMinute(hour)
    if (minute === null) {
      setError("Pick an hour, such as 07:40.")
      return
    }
    save.mutate({ enabled, minute })
  }

  return (
    <form
      noValidate
      className="grid gap-4"
      onSubmit={(e) => {
        e.preventDefault()
        submit()
      }}
    >
      <div className="flex items-start gap-3">
        <Switch
          id={ids.on}
          checked={enabled}
          onCheckedChange={(v) => {
            setSaved(false)
            setEnabled(v)
          }}
          className="mt-0.5"
        />
        <label htmlFor={ids.on} className="text-sm text-fg">
          One mail per provider per day
          <span className="block text-xs text-fg-muted">
            Off sends each report after the waiting time, as before.
          </span>
        </label>
      </div>
      <Field
        id={ids.hour}
        label="Digest hour"
        hint={
          noSmtp
            ? "Set up SMTP above first: the hour belongs to the sending settings."
            : `Your local time (${browserTimeZone()}). Stored in UTC.`
        }
      >
        <Input
          id={ids.hour}
          type="time"
          className="w-36"
          value={hour}
          disabled={noSmtp || !enabled}
          onChange={(e) => {
            setSaved(false)
            setHour(e.target.value)
          }}
        />
      </Field>
      <p className="text-sm text-fg-muted">{DIGEST_EXPLANATION}</p>
      <div className="flex flex-wrap items-center gap-2">
        <Button type="submit" size="sm" disabled={save.isPending}>
          Save
        </Button>
        {saved ? (
          <span role="status" className="text-sm text-fg-muted">
            Saved.
          </span>
        ) : null}
      </div>
      <p role="alert" className="text-sm text-fg empty:hidden">
        {error}
      </p>
    </form>
  )
}

/** Settings, Reporting tab: one daily digest per provider and its hour (M38). */
export function DigestCard() {
  const q = useQuery({ queryKey: digestKeys.digest, queryFn: digestApi.get })
  return (
    <FindingCard
      eyebrow="Daily digest"
      finding={
        q.isPending
          ? "Loading the digest settings…"
          : q.isError
            ? "The digest settings could not be loaded."
            : q.data.enabled
              ? q.data.minute === null
                ? "Each provider gets one mail a day once SMTP is set up."
                : `Each provider gets one mail a day, at ${utcMinuteToLocal(q.data.minute)} your time.`
              : "Daily digests are off: each report goes after the waiting time."
      }
    >
      {q.isPending ? (
        <SkeletonText lines={3} />
      ) : q.data ? (
        <DigestForm key={String(q.data.minute === null)} initial={q.data} />
      ) : null}
    </FindingCard>
  )
}
