import { ChevronsUpDown, KeyRound, Laptop, LogOut, Moon, Sun } from "lucide-react"
import { useState } from "react"
import { Link, useNavigate } from "react-router"
import { ChangePasswordDialog } from "@/components/change-password-dialog"
import { RelativeTime } from "@/components/relative-time"
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuSeparator,
  DropdownMenuSub,
  DropdownMenuSubContent,
  DropdownMenuSubTrigger,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useVersion } from "@/hooks/use-version"
import { ROLE_LABEL } from "@/lib/users"
import { hasUpdate } from "@/lib/version"
import { useAuth } from "./auth"
import { useIpMask } from "./ip-mask"
import { useTheme, type ThemePreference } from "./theme"

const MOCK = import.meta.env.VITE_MOCK === "1"

interface ThemeOption {
  value: ThemePreference
  label: string
  icon: typeof Moon
}

const SYSTEM_THEME: ThemeOption = { value: "system", label: "Match system", icon: Laptop }
const THEMES: ThemeOption[] = [
  { value: "dark", label: "Dark", icon: Moon },
  { value: "light", label: "Light", icon: Sun },
  SYSTEM_THEME,
]

function initials(name: string): string {
  const parts = name.trim().split(/\s+/).filter(Boolean)
  const letters = parts.length > 1 ? [parts[0], parts[parts.length - 1]] : [parts[0] ?? "?"]
  return letters
    .map((p) => (p ?? "?").charAt(0))
    .join("")
    .toUpperCase()
    .slice(0, 2)
}

function Avatar({ name }: { name: string }) {
  return (
    <span
      aria-hidden
      className="grid size-7 shrink-0 place-items-center rounded-full border bg-surface text-2xs font-semibold text-fg-muted"
    >
      {initials(name)}
    </span>
  )
}

/**
 * The profile block at the foot of the sidebar: initials, name and role, opening a menu with the
 * last sign-in, "Change password", the theme, "Mask IP addresses", "Sign out" and the version.
 * `rail` is the avatar alone, for the folded sidebar (the name shows as a tooltip).
 */
export function AccountMenu({
  variant = "full",
  menuSide = "right",
  onNavigate,
}: {
  variant?: "full" | "rail"
  /** Where the menu opens: beside the sidebar on desktop, above the block in the phone drawer. */
  menuSide?: "right" | "top"
  /** Called after a menu entry navigates (closes the phone drawer). */
  onNavigate?: () => void
}) {
  const { user, logout } = useAuth()
  const navigate = useNavigate()
  const { preference, setPreference } = useTheme()
  const { masked, setMasked } = useIpMask()
  const version = useVersion().data
  const [changing, setChanging] = useState(false)
  if (!user) return null
  const role = user.is_owner ? "Owner" : ROLE_LABEL[user.role]
  const roleLine = user.role === "viewer" && !user.is_owner ? `${role}, read-only` : role
  const label = `Account menu for ${user.display_name}`
  const theme = THEMES.find((t) => t.value === preference) ?? SYSTEM_THEME

  const trigger =
    variant === "rail" ? (
      <button
        type="button"
        aria-label={label}
        className="grid size-10 shrink-0 place-items-center rounded-lg transition-colors duration-150 hover:bg-surface-hover focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:outline-none aria-expanded:bg-surface-hover"
      >
        <Avatar name={user.display_name} />
      </button>
    ) : (
      <button
        type="button"
        aria-label={label}
        className="flex h-11 w-full min-w-0 items-center gap-2.5 rounded-lg px-1.5 text-left transition-colors duration-150 hover:bg-surface-hover focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:outline-none aria-expanded:bg-surface-hover lg:h-10"
      >
        <Avatar name={user.display_name} />
        <span className="min-w-0 flex-1">
          <span className="block truncate text-xs font-medium text-fg">{user.display_name}</span>
          <span className="block truncate text-2xs text-fg-subtle">{roleLine}</span>
        </span>
        <ChevronsUpDown aria-hidden className="size-3.5 shrink-0 text-fg-subtle" />
      </button>
    )

  return (
    <>
      <DropdownMenu>
        {variant === "rail" ? (
          <Tooltip>
            <TooltipTrigger asChild>
              <DropdownMenuTrigger asChild>{trigger}</DropdownMenuTrigger>
            </TooltipTrigger>
            <TooltipContent side="right" sideOffset={8}>
              {user.display_name}
            </TooltipContent>
          </Tooltip>
        ) : (
          <DropdownMenuTrigger asChild>{trigger}</DropdownMenuTrigger>
        )}
        <DropdownMenuContent
          side={menuSide}
          align={menuSide === "right" ? "end" : "start"}
          sideOffset={menuSide === "right" ? 10 : 6}
          collisionPadding={8}
          className="w-64"
        >
          <DropdownMenuLabel className="space-y-0.5 font-normal">
            <span className="block truncate text-sm font-medium text-fg">{user.display_name}</span>
            <span className="block truncate text-xs text-fg-muted">
              <span className="font-mono">{user.username}</span>, {roleLine.toLowerCase()}
            </span>
            {user.last_login_at ? (
              <span className="block pt-1 text-xs text-fg-muted">
                Last sign-in <RelativeTime iso={user.last_login_at} className="text-xs" />
              </span>
            ) : null}
          </DropdownMenuLabel>
          <DropdownMenuSeparator />
          {user.is_owner ? (
            <DropdownMenuItem disabled>
              <KeyRound aria-hidden />
              Password is set in .env
            </DropdownMenuItem>
          ) : (
            <DropdownMenuItem onSelect={() => setChanging(true)}>
              <KeyRound aria-hidden />
              Change password
            </DropdownMenuItem>
          )}
          <DropdownMenuSub>
            <DropdownMenuSubTrigger className="gap-2 [&_svg:not([class*='text-'])]:text-muted-foreground">
              <theme.icon aria-hidden className="size-4" />
              <span className="flex-1">Theme</span>
              <span className="text-xs text-fg-subtle">{theme.label}</span>
            </DropdownMenuSubTrigger>
            <DropdownMenuSubContent className="w-44">
              <DropdownMenuRadioGroup
                value={preference}
                onValueChange={(v) => setPreference(v as ThemePreference)}
              >
                {THEMES.map((t) => (
                  <DropdownMenuRadioItem key={t.value} value={t.value}>
                    {t.label}
                  </DropdownMenuRadioItem>
                ))}
              </DropdownMenuRadioGroup>
            </DropdownMenuSubContent>
          </DropdownMenuSub>
          <DropdownMenuCheckboxItem
            checked={masked}
            onCheckedChange={setMasked}
            onSelect={(e) => e.preventDefault()}
          >
            Mask IP addresses
            <span className="sr-only"> (screenshot mode)</span>
          </DropdownMenuCheckboxItem>
          <DropdownMenuSeparator />
          <DropdownMenuItem
            onSelect={() => {
              void logout().finally(() => navigate("/login", { replace: true }))
            }}
          >
            <LogOut aria-hidden />
            Sign out
          </DropdownMenuItem>
          {version || MOCK ? <DropdownMenuSeparator /> : null}
          {version && hasUpdate(version) ? (
            <DropdownMenuItem asChild>
              <Link to="/settings" onClick={onNavigate} className="text-xs font-medium text-fg">
                <span aria-hidden className="mx-1 size-1.5 rounded-full bg-primary" />
                Update available: {version.latest}
              </Link>
            </DropdownMenuItem>
          ) : null}
          {version || MOCK ? (
            <DropdownMenuLabel className="space-y-0.5 py-1 text-2xs font-normal text-fg-subtle">
              {version ? (
                <span
                  className="block font-mono tabular-nums"
                  title={version.commit ? `Commit ${version.commit}` : undefined}
                >
                  SuckerPot {version.version}
                </span>
              ) : null}
              {MOCK ? (
                <span className="block">Mock data: nothing here is real traffic.</span>
              ) : null}
            </DropdownMenuLabel>
          ) : null}
        </DropdownMenuContent>
      </DropdownMenu>
      <ChangePasswordDialog open={changing} onOpenChange={setChanging} username={user.username} />
    </>
  )
}
