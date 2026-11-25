import { useId, useState } from "react"
import { FormError } from "@/components/form-parts"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { describeUserError, UserError } from "@/lib/users"
import { networkApi, validatePseudonym, type NetworkStatus } from "@/lib/network"
import { ProfileFields, type Profile } from "./profile-fields"
import { useRefreshNetwork } from "./use-network"
import { t } from "@/i18n"

function ProfileForm({ status, onClose }: { status: NetworkStatus; onClose: () => void }) {
  const refresh = useRefreshNetwork()
  const [profile, setProfile] = useState<Profile>({
    pseudonym: status.pseudonym ?? "",
    country: status.country ?? "",
    showCountry: status.show_country,
  })
  const [nameError, setNameError] = useState<string | undefined>()
  const [formError, setFormError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)
  const errId = useId()

  async function submit() {
    if (pending) return
    const problem = validatePseudonym(profile.pseudonym)
    setNameError(problem ?? undefined)
    setFormError(null)
    if (problem) return
    setPending(true)
    try {
      await networkApi.update(profile)
      await refresh()
      onClose()
    } catch (e) {
      const detail = e instanceof UserError && e.detail ? e.detail : describeUserError(e)
      if (e instanceof UserError && (e.reason === "taken" || e.reason === "invalid"))
        setNameError(detail)
      else setFormError(detail)
    } finally {
      setPending(false)
    }
  }

  return (
    <form
      className="flex flex-col gap-4"
      noValidate
      onSubmit={(e) => {
        e.preventDefault()
        void submit()
      }}
    >
      <DialogHeader className="text-left">
        <DialogTitle>{t("network_profile_title")}</DialogTitle>
        <DialogDescription>{t("network_profile_description")}</DialogDescription>
      </DialogHeader>
      <ProfileFields value={profile} onChange={setProfile} pseudonymError={nameError} />
      <FormError id={errId} message={formError} />
      <DialogFooter>
        <Button type="button" variant="outline" onClick={onClose}>
          {t("common_cancel")}
        </Button>
        <Button type="submit" disabled={pending}>
          {pending ? t("network_profile_saving") : t("common_save")}
        </Button>
      </DialogFooter>
    </form>
  )
}

/** Change the pseudonym or the country of a member. No password: nothing new is shared. */
export function ProfileDialog({
  open,
  onOpenChange,
  status,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  status: NetworkStatus
}) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="bg-popover">
        <ProfileForm status={status} onClose={() => onOpenChange(false)} />
      </DialogContent>
    </Dialog>
  )
}
