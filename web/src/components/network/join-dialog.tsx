import { ChevronRight } from "lucide-react"
import { useId, useState } from "react"
import { AdminActionDialog } from "@/components/users/admin-action-dialog"
import { ALL_CONSENTS, NETWORK_MESSAGES, networkApi, validatePseudonym } from "@/lib/network"
import { UserError } from "@/lib/users"
import { ProfileFields, type Profile } from "./profile-fields"
import { useRefreshNetwork } from "./use-network"
import { WhatYouShare } from "./what-you-share"
import { t } from "@/i18n"

const EMPTY: Profile = { pseudonym: "", country: "", showCountry: false }

/**
 * Joining is one button and the password. The five consents are shown as a read-only list and all
 * five are sent. The pseudonym and country are optional and stay collapsed.
 */
export function JoinDialog({
  open,
  onOpenChange,
  onJoined,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  onJoined?: () => void
}) {
  const refresh = useRefreshNetwork()
  const [profile, setProfile] = useState<Profile>(EMPTY)
  const [nameError, setNameError] = useState<string | undefined>()
  const [more, setMore] = useState(false)
  const group = useId()

  // Closing drops everything typed, so the next opening starts blank.
  const reset = () => {
    setProfile(EMPTY)
    setNameError(undefined)
    setMore(false)
  }

  return (
    <AdminActionDialog
      open={open}
      onOpenChange={(next) => {
        if (!next) reset()
        onOpenChange(next)
      }}
      title={t("network_join_title")}
      description={t("network_join_description")}
      hint={t("network_join_password_hint")}
      focusPassword={false}
      confirmLabel={t("network_join_button")}
      pendingLabel={t("network_join_pending")}
      validate={() => {
        const problem = validatePseudonym(profile.pseudonym)
        setNameError(problem ?? undefined)
        if (problem) {
          setMore(true)
          return t("network_join_check_pseudonym")
        }
        return null
      }}
      run={async (password) => {
        try {
          await networkApi.join(
            {
              pseudonym: profile.pseudonym,
              country: profile.country,
              showCountry: profile.showCountry,
              accept: [...ALL_CONSENTS],
            },
            password,
          )
        } catch (e) {
          // A join is already recorded: show the pending state behind the dialog.
          if (e instanceof UserError && e.detail === NETWORK_MESSAGES.already) void refresh()
          throw e
        }
      }}
      onDone={() => {
        void refresh()
        onJoined?.()
      }}
    >
      <WhatYouShare />
      <div className="space-y-3">
        <button
          type="button"
          onClick={() => setMore((v) => !v)}
          aria-expanded={more}
          aria-controls={`${group}-profile`}
          className="flex items-center gap-1.5 rounded-sm text-sm font-medium text-fg-muted hover:text-fg focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:outline-none"
        >
          <ChevronRight
            aria-hidden
            className={
              more ? "size-4 rotate-90 transition-transform" : "size-4 transition-transform"
            }
          />
          {t("network_join_optional_profile")}
        </button>
        <div id={`${group}-profile`} hidden={!more}>
          <ProfileFields value={profile} onChange={setProfile} pseudonymError={nameError} />
        </div>
      </div>
    </AdminActionDialog>
  )
}
