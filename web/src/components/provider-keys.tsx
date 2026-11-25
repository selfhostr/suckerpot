import { useMutation, useQueryClient } from "@tanstack/react-query"
import {
  CircleCheck,
  CircleDashed,
  LoaderCircle,
  TriangleAlert,
  type LucideIcon,
} from "lucide-react"
import { useState } from "react"
import { Meter } from "@/components/meter"
import { RemoveKeyDialog, SetKeyDialog } from "@/components/provider-key-dialogs"
import { useAuth } from "@/app/auth"
import { RelativeTime } from "@/components/relative-time"
import { t } from "@/i18n"
import { tNodes } from "@/i18n/rich"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { queryKeys } from "@/lib/api"
import { formatNumber, formatPercent } from "@/lib/format"
import { describeKeyError, PROVIDER_NAMES, requestKeyTest } from "@/lib/provider-keys"
import {
  keyInFlight,
  secretErrorMessage,
  sourceLabel,
  testMessage,
  usageTone,
  type EnrichmentSettings,
  type KeyInfo,
  type ProviderId,
  type ReputationProvider,
} from "@/lib/settings"
import { cn } from "@/lib/utils"

interface State {
  label: string
  icon: LucideIcon
  className: string
}

function stateOf(k: KeyInfo | ReputationProvider): State {
  if (!k.configured)
    return {
      label: t("providerkeys_state_not_configured"),
      icon: CircleDashed,
      className: "text-fg-muted",
    }
  if ("disabled" in k && k.disabled)
    return { label: t("common_disabled"), icon: TriangleAlert, className: "text-sev-warning" }
  if ("paused" in k && k.paused)
    return {
      label: t("providerkeys_state_paused"),
      icon: TriangleAlert,
      className: "text-sev-warning",
    }
  return { label: t("common_on"), icon: CircleCheck, className: "text-status-ok" }
}

function isReputation(k: KeyInfo): k is ReputationProvider {
  return "daily_quota" in k
}

function KeyRow({
  id,
  info,
  editable,
  readOnly,
  envName,
}: {
  id: ProviderId
  info: KeyInfo | ReputationProvider
  editable: boolean
  /** A viewer: no control that changes anything is shown. */
  readOnly: boolean
  envName: string
}) {
  const name = PROVIDER_NAMES[id]
  const client = useQueryClient()
  const refresh = () => client.invalidateQueries({ queryKey: queryKeys.enrichmentSettings })
  const [testError, setTestError] = useState<string | null>(null)
  const test = useMutation({
    mutationFn: () => requestKeyTest(id),
    onMutate: () => setTestError(null),
    onSuccess: refresh,
    onError: (e) => setTestError(describeKeyError(e)),
  })
  const state = stateOf(info)
  const StateIcon = state.icon
  const hasSavedKey = info.source === "settings" || info.secret_error !== null
  const message = testMessage(info)
  const problem = secretErrorMessage(info.secret_error)
  const testing = test.isPending || message?.tone === "pending"
  const quota = isReputation(info) ? (info.daily_quota ?? 0) : 0

  return (
    <li className="flex flex-col gap-3 rounded-lg border bg-bg p-4">
      <div className="flex items-center justify-between gap-3">
        <span className="type-subtitle text-fg">{name}</span>
        <span
          className={cn("inline-flex items-center gap-1.5 text-xs font-medium", state.className)}
        >
          <StateIcon aria-hidden className="size-3.5" strokeWidth={2.25} />
          {state.label}
        </span>
      </div>

      <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1.5 text-xs text-fg-muted">
        <Badge variant="outline" className="text-fg-muted">
          {sourceLabel(info.source)}
        </Badge>
        {info.last4 ? (
          <span>
            {tNodes(
              "providerkeys_key_ending",
              {},
              { last4: <span className="font-mono text-fg">{info.last4}</span> },
            )}
          </span>
        ) : null}
        {info.updated_at ? (
          <span>
            {tNodes(
              "providerkeys_updated",
              {},
              { time: <RelativeTime iso={info.updated_at} className="text-xs" /> },
            )}
          </span>
        ) : null}
      </div>

      {isReputation(info) && info.configured && quota > 0 ? (
        <div className="space-y-2">
          <Meter
            value={info.used_today}
            max={quota}
            label={t("providerkeys_meter_label", { name })}
            valueText={t("settings_storage_of", {
              size: formatNumber(info.used_today),
              max: formatNumber(quota),
            })}
            tone={usageTone(info.used_today / quota)}
          />
          <p className="text-xs text-fg-muted">
            {t("providerkeys_usage", {
              used: formatNumber(info.used_today),
              quota: formatNumber(quota),
              percent: formatPercent(info.used_today / quota),
            })}
          </p>
        </div>
      ) : null}

      {!info.configured && !readOnly ? (
        <p className="text-xs text-fg-muted">
          {editable
            ? t("providerkeys_add_key")
            : tNodes(
                "providerkeys_set_env",
                {},
                {
                  name: <code className="font-mono text-fg">{envName}</code>,
                  env: <code className="font-mono">.env</code>,
                },
              )}
        </p>
      ) : null}

      {isReputation(info) && (info.disabled || info.last_error) ? (
        <p className="text-xs text-sev-warning">{info.disabled ?? info.last_error}</p>
      ) : null}
      {problem ? <p className="text-xs text-sev-warning">{problem}</p> : null}
      {info.pending_apply ? (
        <p role="status" className="text-xs text-fg-muted">
          {t("providerkeys_saved")}
        </p>
      ) : null}

      <div role="status" aria-live="polite" className="empty:hidden">
        {testError ? (
          <p className="text-xs text-sev-warning">{testError}</p>
        ) : message && message.tone !== "pending" ? (
          <p
            className={cn("text-xs", message.tone === "ok" ? "text-status-ok" : "text-sev-warning")}
          >
            {message.text}
            {info.test?.checked_at ? (
              <>
                {" "}
                <RelativeTime iso={info.test.checked_at} className="text-xs" />
              </>
            ) : null}
          </p>
        ) : null}
      </div>
      {readOnly ? null : (
        // Pinned to the bottom, so the actions of tiles side by side share one line.
        <div className="mt-auto flex flex-wrap items-center gap-2">
          <SetKeyDialog
            provider={id}
            replacing={info.source === "settings"}
            onDone={() => void refresh()}
            trigger={
              <Button
                variant="outline"
                size="sm"
                disabled={!editable}
                aria-label={
                  info.source === "settings"
                    ? t("providerkeys_replace_label", { name })
                    : t("providerkeys_set_label", { name })
                }
              >
                {info.source === "settings" ? t("providerkeys_replace") : t("providerkeys_set")}
              </Button>
            }
          />
          {hasSavedKey ? (
            <RemoveKeyDialog
              provider={id}
              onDone={() => void refresh()}
              trigger={
                <Button
                  variant="ghost"
                  size="sm"
                  disabled={!editable}
                  aria-label={t("providerkeys_remove_label", { name })}
                >
                  {t("common_remove")}
                </Button>
              }
            />
          ) : null}
          {info.configured ? (
            <Button
              variant="ghost"
              size="sm"
              disabled={testing || keyInFlight(info)}
              onClick={() => test.mutate()}
              aria-label={t("providerkeys_test_label", { name })}
              aria-busy={testing || undefined}
            >
              {testing ? <LoaderCircle aria-hidden className="animate-spin" /> : null}
              {testing ? t("providerkeys_testing") : t("providerkeys_test")}
            </Button>
          ) : null}
        </div>
      )}
    </li>
  )
}

/** Shows environment variable names and `.env` from a server sentence in monospace. */
function WithCode({ text }: { text: string }) {
  return (
    <>
      {text.split(/(\b[A-Z][A-Z0-9]*_[A-Z0-9_]+\b|\.env\b)/).map((part, i) =>
        i % 2 === 1 ? (
          <code key={i} className={cn("font-mono", part !== ".env" && "text-fg")}>
            {part}
          </code>
        ) : (
          part
        ),
      )}
    </>
  )
}

/** The three provider keys: where each comes from, and the dialogs to change them. */
export function ProviderKeys({ e }: { e: EnrichmentSettings }) {
  const { canWrite } = useAuth()
  const readOnly = !canWrite
  const editable = e.key_editing.enabled
  return (
    <div className="space-y-4">
      <div className="space-y-1">
        <h4 className="type-subtitle text-fg">{t("providerkeys_title")}</h4>
        {readOnly ? (
          <p className="text-xs text-fg-muted">{t("providerkeys_readonly")}</p>
        ) : editable ? (
          <p className="text-xs text-fg-muted">
            {tNodes("providerkeys_editable", {}, { env: <code className="font-mono">.env</code> })}
          </p>
        ) : (
          <p className="text-xs text-fg-muted">
            {tNodes(
              "providerkeys_locked",
              {},
              {
                reason: (
                  <WithCode text={e.key_editing.reason ?? t("providerkeys_locked_default")} />
                ),
                env: <code className="font-mono">.env</code>,
              },
            )}
          </p>
        )}
      </div>
      <ul
        aria-label={t("providerkeys_title")}
        className="grid gap-3 md:grid-cols-2 2xl:grid-cols-3"
      >
        <KeyRow
          id="abuseipdb"
          info={e.abuseipdb}
          editable={editable}
          readOnly={readOnly}
          envName="ABUSEIPDB_API_KEY"
        />
        <KeyRow
          id="greynoise"
          info={e.greynoise}
          editable={editable}
          readOnly={readOnly}
          envName="GREYNOISE_API_KEY"
        />
        <KeyRow
          id="maxmind"
          info={e.maxmind}
          editable={editable}
          readOnly={readOnly}
          envName="MAXMIND_LICENSE_KEY"
        />
        <KeyRow
          id="nvd"
          info={e.nvd}
          editable={editable}
          readOnly={readOnly}
          envName="NVD_API_KEY"
        />
        <KeyRow
          id="github"
          info={e.github}
          editable={editable}
          readOnly={readOnly}
          envName="GITHUB_ADVISORY_TOKEN"
        />
      </ul>
      <div className="space-y-1 pt-2">
        <h4 className="type-subtitle text-fg">{t("providerkeys_threat_title")}</h4>
        <p className="text-xs text-fg-muted">{t("providerkeys_threat_description")}</p>
      </div>
      <ul
        aria-label={t("providerkeys_threat_label")}
        className="grid gap-3 md:grid-cols-2 2xl:grid-cols-3"
      >
        <KeyRow
          id="abusech"
          info={e.abusech}
          editable={editable}
          readOnly={readOnly}
          envName="ABUSECH_AUTH_KEY"
        />
        <KeyRow
          id="virustotal"
          info={e.virustotal}
          editable={editable}
          readOnly={readOnly}
          envName="VIRUSTOTAL_API_KEY"
        />
      </ul>
    </div>
  )
}
