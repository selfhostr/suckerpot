import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { Link, useNavigate } from "react-router"
import { useAuth } from "@/app/auth"
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
      eyebrow="First-run setup"
      finding={
        unfinished
          ? `The setup wizard is not finished. ${describeProgress(p, WIZARD_STEPS)}`
          : p.state === "skipped"
            ? "You skipped the setup. You can run it whenever you like."
            : "You went through the setup wizard. The checklist below shows what the running stack still lacks, and you can open the wizard again whenever you like."
      }
      detail="It walks through the sensors, the router ports, the VPN, your own address, reports and alerts."
      action={
        unfinished ? (
          <Button asChild size="sm">
            <Link to="/setup">Resume the setup</Link>
          </Button>
        ) : (
          <Button
            size="sm"
            variant="outline"
            disabled={reopen.isPending}
            onClick={() => reopen.mutate()}
          >
            Open the setup again
          </Button>
        )
      }
    />
  )
}
