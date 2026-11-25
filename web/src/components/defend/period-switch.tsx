import { t } from "@/i18n"
import { SegmentedControl } from "@/components/segmented-control"
import { PERIOD_DAYS } from "@/lib/defend"

export function PeriodSwitch({
  days,
  onChange,
}: {
  days: number
  onChange: (days: number) => void
}) {
  return (
    <SegmentedControl
      label={t("defend_period")}
      value={String(days)}
      onChange={(v) => onChange(Number(v))}
      options={PERIOD_DAYS.map((d) => ({
        value: String(d),
        label: t("defend_period_days", { count: d }),
      }))}
    />
  )
}
