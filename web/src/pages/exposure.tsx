import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { Plus, SearchX, ServerCog, ShieldQuestion } from "lucide-react"
import { useState } from "react"
import { useAuth } from "@/app/auth"
import { t } from "@/i18n"
import { PeriodSwitch } from "@/components/defend/period-switch"
import { Checks, ExposureCard } from "@/components/defend/exposure-card"
import { InventoryDialog } from "@/components/defend/inventory-dialog"
import { EmptyState } from "@/components/empty-state"
import { usePeriod } from "@/hooks/use-period"
import { PageHeader } from "@/components/page-header"
import { ReadOnlyBadge } from "@/components/read-only-badge"
import { SensorBadge } from "@/components/sensor-badge"
import { SkeletonCard } from "@/components/skeletons"
import { Button } from "@/components/ui/button"
import {
  defendApi,
  defendKeys,
  deleteInventory,
  exposureSentence,
  serviceLabel,
  type InventoryItem,
} from "@/lib/defend"

type DialogState = { item: InventoryItem | null; preset: string | null } | null

export function ExposurePage() {
  const { canWrite } = useAuth()
  const queryClient = useQueryClient()
  const [days, setDays] = usePeriod()
  const [dialog, setDialog] = useState<DialogState>(null)

  const report = useQuery({
    queryKey: defendKeys.exposure(days),
    queryFn: () => defendApi.exposure(days),
  })
  const remove = useMutation({
    mutationFn: (item: InventoryItem) => deleteInventory(item.id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["defend"] }),
  })
  const r = report.data

  return (
    <>
      <PageHeader
        help="exposure"
        title={t("exposure_title")}
        description={exposureSentence(r, days)}
        actions={
          <>
            <ReadOnlyBadge />
            {canWrite ? (
              <Button size="sm" onClick={() => setDialog({ item: null, preset: null })}>
                <Plus aria-hidden />
                {t("exposure_add")}
              </Button>
            ) : null}
          </>
        }
      />

      <div className="mb-6 flex items-start gap-2.5 rounded-lg border border-dashed px-4 py-3 text-sm text-fg-muted">
        <ShieldQuestion aria-hidden className="mt-0.5 size-4 shrink-0" />
        <p>
          {t("exposure_privacy")}
        </p>
      </div>

      <div className="mb-4 flex flex-wrap items-center gap-3">
        <PeriodSwitch days={days} onChange={setDays} />
      </div>

      {report.isPending ? (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          <SkeletonCard />
          <SkeletonCard />
        </div>
      ) : report.isError || !r ? (
        <EmptyState
          icon={SearchX}
          title={t("exposure_load_error")}
          description={t("exposure_load_error_hint")}
          action={
            <Button variant="outline" size="sm" onClick={() => void report.refetch()}>
              {t("common_try_again")}
            </Button>
          }
        />
      ) : (
        <>
          {r.services.length === 0 ? (
            <EmptyState
              icon={ServerCog}
              title={t("exposure_empty_title")}
              description={t("exposure_empty_description")}
              action={
                canWrite ? (
                  <Button onClick={() => setDialog({ item: null, preset: null })}>
                    <Plus aria-hidden />
                    {t("exposure_add")}
                  </Button>
                ) : undefined
              }
            />
          ) : (
            <ul aria-label={t("exposure_services")} className="grid grid-cols-1 gap-4 lg:grid-cols-2">
              {r.services.map((s) => (
                <li key={s.item.id} className="flex *:w-full">
                  <ExposureCard
                    service={s}
                    canWrite={canWrite}
                    onEdit={(item) => setDialog({ item, preset: null })}
                    onRemove={(item) => remove.mutate(item)}
                  />
                </li>
              ))}
            </ul>
          )}

          {r.unlisted.length > 0 ? (
            <section aria-labelledby="unlisted" className="mt-10">
              <h2 id="unlisted" className="type-section-title text-fg">
                {t("exposure_unlisted_title")}
              </h2>
              <p className="mt-1.5 max-w-2xl type-lede text-fg-muted">
                {t("exposure_unlisted_description", { count: r.unlisted.length })}
              </p>
              <ul className="mt-5 grid grid-cols-1 gap-4 lg:grid-cols-2">
                {r.unlisted.map((u) => (
                  <li
                    key={u.service}
                    className="flex flex-col gap-4 rounded-lg border bg-surface p-4 shadow-sm sm:p-5"
                  >
                    <div className="flex flex-wrap items-start justify-between gap-3">
                      <div className="space-y-1.5">
                        <SensorBadge sensor={u.service} />
                        <p className="text-sm text-fg">
                          {t("exposure_unlisted_evidence", {
                            sessions: u.sessions,
                            sources: u.sources,
                            days,
                          })}
                        </p>
                      </div>
                      {canWrite ? (
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => setDialog({ item: null, preset: u.service })}
                        >
                          <Plus aria-hidden />
                          {t("exposure_unlisted_add", { service: serviceLabel(u.service) })}
                        </Button>
                      ) : null}
                    </div>
                    <Checks checks={u.checks} title={t("exposure_unlisted_check")} />
                  </li>
                ))}
              </ul>
            </section>
          ) : null}
        </>
      )}

      {dialog ? (
        <InventoryDialog
          open
          onOpenChange={(open) => {
            if (!open) setDialog(null)
          }}
          item={dialog.item}
          preset={dialog.preset}
        />
      ) : null}
    </>
  )
}
