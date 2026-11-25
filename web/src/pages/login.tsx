import { CircleAlert } from "lucide-react"
import { useId, useState, type SyntheticEvent } from "react"
import { Navigate, useSearchParams } from "react-router"
import { AUTH_BYPASS, useAuth } from "@/app/auth"
import { Logo } from "@/app/logo"
import { ThemeToggle } from "@/components/theme-toggle"
import { Button } from "@/components/ui/button"
import { Card } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { LoginError, safeNext, type LoginFailure } from "@/lib/auth-api"

const MESSAGES: Record<LoginFailure, string> = {
  invalid: "Invalid username or password",
  "rate-limited": "Too many attempts. Wait a minute, then try again.",
  origin: "This address is not allowed to sign in. Open the dashboard at its usual address.",
  network: "The server could not be reached. Try again in a moment.",
}

export function LoginPage() {
  const { status, signedOut, login } = useAuth()
  const [params] = useSearchParams()
  const next = safeNext(params.get("next"))
  const [username, setUsername] = useState("")
  const [password, setPassword] = useState("")
  const [failure, setFailure] = useState<LoginFailure | null>(null)
  const [pending, setPending] = useState(false)
  const userId = useId()
  const passId = useId()
  const errorId = useId()

  if (status === "authenticated" && !signedOut && !AUTH_BYPASS) {
    return <Navigate to={next} replace />
  }

  async function submit() {
    if (pending) return
    setPending(true)
    setFailure(null)
    try {
      await login(username, password)
    } catch (e) {
      setFailure(e instanceof LoginError ? e.reason : "network")
      setPassword("")
    } finally {
      setPending(false)
    }
  }

  const invalid = failure === "invalid"
  return (
    <div className="relative flex min-h-dvh flex-col items-center justify-center bg-bg px-4 py-12">
      <div className="absolute top-4 right-4">
        <ThemeToggle />
      </div>
      <main className="flex w-full max-w-sm flex-col items-center gap-8">
        <Logo />
        <Card className="w-full gap-6 border bg-surface p-6 shadow-none sm:p-8">
          <div className="space-y-1.5 text-center">
            <h1 className="type-page-title text-fg">Sign in</h1>
            <p className="text-sm text-fg-muted">Enter your credentials to open the dashboard.</p>
          </div>
          <form
            onSubmit={(event: SyntheticEvent) => {
              event.preventDefault()
              void submit()
            }}
            className="flex flex-col gap-4"
            noValidate
          >
            <div className="flex flex-col gap-1.5">
              <label htmlFor={userId} className="text-sm font-medium text-fg">
                Username
              </label>
              <Input
                id={userId}
                name="username"
                autoComplete="username"
                autoCapitalize="none"
                autoCorrect="off"
                spellCheck={false}
                autoFocus
                required
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                aria-invalid={invalid || undefined}
                aria-describedby={failure ? errorId : undefined}
              />
            </div>
            <div className="flex flex-col gap-1.5">
              <label htmlFor={passId} className="text-sm font-medium text-fg">
                Password
              </label>
              <Input
                id={passId}
                name="password"
                type="password"
                autoComplete="current-password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                aria-invalid={invalid || undefined}
                aria-describedby={failure ? errorId : undefined}
              />
            </div>
            <div id={errorId} role="alert" aria-live="assertive" className="empty:hidden">
              {failure ? (
                <p className="flex items-start gap-2 rounded-md border border-border-strong bg-surface-raised px-3 py-2 text-sm text-fg">
                  <CircleAlert aria-hidden className="mt-0.5 size-4 shrink-0 text-fg-muted" />
                  {MESSAGES[failure]}
                </p>
              ) : null}
            </div>
            <Button type="submit" size="lg" disabled={pending || !username || !password}>
              {pending ? "Signing in…" : "Sign in"}
            </Button>
          </form>
        </Card>
      </main>
    </div>
  )
}
