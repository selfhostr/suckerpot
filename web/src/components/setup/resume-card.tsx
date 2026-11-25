import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { Link, useNavigate } from "react-router"
import { useAuth } from "@/app/auth"
import { t } from "@/i18n"
import { FindingCard } from "@/components/finding-card"
import { Button } from "@/components/ui/button"
import { describeProgress, WIZARD_STEPS, wizardApi, wizardKeys } from "@/lib/setup-wizard"

/** Settings, General tab: resume an unfinished setup, or open it again. Administrators only. */
export function SetupResumeCard() {
  const { canWrite } = useAuth()
  const qc = useQueryClient()
  const navigate = useNavigate()
  const q = useQuery({
    queryKey: wizardKeys.progress,
    queryFn: wizardApi.progress,
    enabled: canWrite,
  })
  const reopen = useMutation({
    mutationFn: () => wizardApi.change({ reopen: true }),
    onSuccess: (data) => {
      qc.setQueryData(wizardKeys.progress, data)
      void navigate("/setup?step=welcome")
    },
  })
  const p = q.data
  if (!canWrite || !p) return null
  const unfinished = p.state === "new" || p.state === "in_progress"
  return (
    <FindingCard
      eyebrow={t("setup_resume_title")}
      finding={
        unfinished
          ? t("setup_resume_unfinished", { progress: describeProgress(p, WIZARD_STEPS) })
          : p.state === "skipped"
            ? t("setup_resume_skipped")
            : t("setup_resume_finished")
      }
      detail={t("setup_resume_detail")}
      action={
        unfinished ? (
          <Button asChild size="sm">
            <Link to="/setup">{t("setup_resume_button")}</Link>
          </Button>
        ) : (
          <Button
            size="sm"
            variant="outline"
            disabled={reopen.isPending}
            onClick={() => reopen.mutate()}
          >
            {t("setup_resume_reopen")}
          </Button>
        )
      }
    />
  )
}
