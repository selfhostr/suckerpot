import { ChevronsUpDown, KeyRound, Laptop, LogOut, Moon, Sun } from "lucide-react"
import { useState } from "react"
import { useNavigate } from "react-router"
import { ChangePasswordDialog } from "@/components/change-password-dialog"
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useAuth } from "./auth"
import { useIpMask } from "./ip-mask"
import { useTheme, type ThemePreference } from "./theme"

/** One item cycles the theme, light → dark → system, and shows the one in use. */
const THEMES: Record<ThemePreference, { label: string; icon: typeof Moon; next: ThemePreference }> =
  {
    light: { label: "Light", icon: Sun, next: "dark" },
    dark: { label: "Dark", icon: Moon, next: "system" },
    system: { label: "System", icon: Laptop, next: "light" },
  }

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
 * The profile block at the foot of the sidebar: initials and name, opening a short menu: the
 * theme (one item that cycles), "Mask IP addresses", "Change password" (not for the owner, whose
 * password lives in .env) and "Sign out". The version is at the foot of every page instead.
 * `rail` is the avatar alone, for the folded sidebar (the name shows as a tooltip).
 */
export function AccountMenu({
  variant = "full",
  menuSide = "right",
}: {
  variant?: "full" | "rail"
  /** Where the menu opens: beside the sidebar on desktop, above the block in the phone drawer. */
  menuSide?: "right" | "top"
}) {
  const { user, logout } = useAuth()
  const navigate = useNavigate()
  const { preference, setPreference } = useTheme()
  const { masked, setMasked } = useIpMask()
  const [changing, setChanging] = useState(false)
  if (!user) return null
  const label = `Account menu for ${user.display_name}`
  const theme = THEMES[preference]

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
        className="flex h-10 w-full min-w-0 items-center gap-2.5 rounded-lg px-1.5 text-left transition-colors duration-150 hover:bg-surface-hover focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:outline-none aria-expanded:bg-surface-hover"
      >
        <Avatar name={user.display_name} />
        <span className="min-w-0 flex-1 truncate text-sm font-medium text-fg">
          {user.display_name}
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
          className="w-56"
        >
          <DropdownMenuItem
            // The menu stays open, so the new theme is seen before moving on.
            onSelect={(e) => {
              e.preventDefault()
              setPreference(theme.next)
            }}
          >
            <theme.icon aria-hidden />
            <span className="flex-1">Theme</span>
            <span className="text-xs text-fg-subtle">{theme.label}</span>
            <span className="sr-only">, switches to {THEMES[theme.next].label.toLowerCase()}</span>
          </DropdownMenuItem>
          <DropdownMenuCheckboxItem
            checked={masked}
            onCheckedChange={setMasked}
            onSelect={(e) => e.preventDefault()}
          >
            Mask IP addresses
            <span className="sr-only"> (screenshot mode)</span>
          </DropdownMenuCheckboxItem>
          <DropdownMenuSeparator />
          {user.is_owner ? null : (
            <DropdownMenuItem onSelect={() => setChanging(true)}>
              <KeyRound aria-hidden />
              Change password
            </DropdownMenuItem>
          )}
          <DropdownMenuItem
            onSelect={() => {
              void logout().finally(() => navigate("/login", { replace: true }))
            }}
          >
            <LogOut aria-hidden />
            Sign out
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
      <ChangePasswordDialog open={changing} onOpenChange={setChanging} username={user.username} />
    </>
  )
}
