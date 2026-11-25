import { useId } from "react"
import { FindingCard } from "@/components/finding-card"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { LOCALES, currentLocale, isLocaleCode, setLocale, t } from "@/i18n"

/** Settings, General tab: the language of the dashboard. Kept in this browser, like the theme. */
export function LanguageCard() {
  // The root remounts the tree when the language changes, so this always reads the current one.
  const locale = currentLocale()
  const id = useId()
  const name = LOCALES.find((l) => l.code === locale)?.name ?? locale
  return (
    <FindingCard
      eyebrow={t("account_language")}
      finding={t("settings_language_finding", { language: name })}
      detail={t("settings_language_detail")}
      help="language"
    >
      <label htmlFor={id} className="sr-only">
        {t("account_language")}
      </label>
      <Select
        value={locale}
        onValueChange={(code) => {
          if (isLocaleCode(code)) void setLocale(code, true)
        }}
      >
        <SelectTrigger id={id} className="w-full sm:w-64">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {LOCALES.map((l) => (
            <SelectItem key={l.code} value={l.code} lang={l.code}>
              {l.name}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </FindingCard>
  )
}
