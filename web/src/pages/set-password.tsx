import { KeyRound } from "lucide-react"
import { Navigate, useNavigate } from "react-router"
import { useAuth } from "@/app/auth"
import { Logo } from "@/app/logo"
import { ChangePasswordForm } from "@/components/password-form"
import { ThemeToggle } from "@/components/theme-toggle"
import { Card } from "@/components/ui/card"

/** The first screen of a new account, or of one whose password an administrator reset. */
export function SetPasswordPage() {
  const { status, user, refresh, logout } = useAuth()
  const navigate = useNavigate()

  if (status === "anonymous") return <Navigate to="/login" replace />
  if (status === "authenticated" && user && !user.must_change_password)
    return <Navigate to="/overview" replace />
  if (!user) return null

  return (
    <div className="relative flex min-h-dvh flex-col items-center justify-center bg-bg px-4 py-12">
      <div className="absolute top-4 right-4">
        <ThemeToggle />
      </div>
      <main className="flex w-full max-w-sm flex-col items-center gap-8">
        <Logo />
        <Card className="w-full gap-6 border bg-surface p-6 shadow-none sm:p-8">
          <div className="space-y-1.5 text-center">
            <span
              aria-hidden
              className="mx-auto mb-2 grid size-9 place-items-center rounded-full border bg-bg text-fg-muted"
            >
              <KeyRound className="size-4" />
            </span>
            <h1 className="type-page-title text-fg">Set your password</h1>
            <p className="text-sm text-fg-muted">
              Hello {user.display_name}. The password you signed in with is temporary. Choose your
              own to open the dashboard.
            </p>
          </div>
          <ChangePasswordForm
            username={user.username}
            currentLabel="Temporary password"
            submitLabel="Save and continue"
            layout="page"
            onDone={() => {
              void refresh().then(() => navigate("/overview", { replace: true }))
            }}
          />
          <button
            type="button"
            onClick={() => {
              void logout().finally(() => navigate("/login", { replace: true }))
            }}
            className="text-center text-xs text-fg-muted underline-offset-4 hover:text-fg hover:underline"
          >
            Sign out instead
          </button>
        </Card>
      </main>
    </div>
  )
}
