import { Laptop, Moon, Sun } from "lucide-react"
import { useTheme, type ThemePreference } from "@/app/theme"
import { SegmentedControl } from "@/components/segmented-control"
import { t, tk } from "@/i18n"
import { withText } from "@/lib/utils"

const OPTIONS = [
  withText(
    { ariaLabel: tk("ui_theme_dark") },
    { value: "dark" as const, label: <Moon aria-hidden className="size-3.5" /> },
  ),
  withText(
    { ariaLabel: tk("ui_theme_light") },
    { value: "light" as const, label: <Sun aria-hidden className="size-3.5" /> },
  ),
  withText(
    { ariaLabel: tk("ui_theme_system") },
    { value: "system" as const, label: <Laptop aria-hidden className="size-3.5" /> },
  ),
] as const satisfies readonly {
  value: ThemePreference
  ariaLabel: string
  label: React.ReactNode
}[]

export function ThemeToggle({ className }: { className?: string }) {
  const { preference, setPreference } = useTheme()
  return (
    <SegmentedControl
      label={t("ui_theme")}
      size="icon"
      value={preference}
      onChange={setPreference}
      options={OPTIONS}
      className={className}
    />
  )
}
