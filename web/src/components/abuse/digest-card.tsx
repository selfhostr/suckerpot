import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { useId, useState } from "react"
import { Field } from "@/components/form-parts"
import { FindingCard } from "@/components/finding-card"
import { SkeletonText } from "@/components/skeletons"
import { Button } from "@/components/ui/button"
import { t } from "@/i18n"
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
      setError(t("digest_hour_invalid", { example: "07:40" }))
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
          {t("digest_toggle")}
          <span className="block text-xs text-fg-muted">{t("digest_toggle_hint")}</span>
        </label>
      </div>
      <Field
        id={ids.hour}
        label={t("digest_hour_label")}
        hint={
          noSmtp
            ? t("digest_hour_hint_no_smtp")
            : t("digest_hour_hint", { zone: browserTimeZone() })
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
      <p className="text-sm text-fg-muted">
        {t("digest_explanation", { max: 100, hours: 2, parts: 3 })}
      </p>
      <div className="flex flex-wrap items-center gap-2">
        <Button type="submit" disabled={save.isPending}>
          {t("common_save")}
        </Button>
        {saved ? (
          <span role="status" className="text-sm text-fg-muted">
            {t("digest_saved")}
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
      eyebrow={t("digest_eyebrow")}
      finding={
        q.isPending
          ? t("digest_loading")
          : q.isError
            ? t("digest_load_failed")
            : q.data.enabled
              ? q.data.minute === null
                ? t("digest_finding_no_smtp")
                : t("digest_finding_at", { time: utcMinuteToLocal(q.data.minute) })
              : t("digest_finding_off")
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
