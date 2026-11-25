import { useId, useMemo } from "react"
import { Field } from "@/components/form-parts"
import { Input } from "@/components/ui/input"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Switch } from "@/components/ui/switch"
import { countryOptions } from "@/lib/network"
import { t } from "@/i18n"

const NONE = "none"

export interface Profile {
  pseudonym: string
  country: string
  showCountry: boolean
}

/**
 * The two optional things a member may choose: a pseudonym and a country. Both start empty. The
 * country is never guessed, and showing it next to the pseudonym is a separate switch, off.
 */
export function ProfileFields({
  value,
  onChange,
  pseudonymError,
}: {
  value: Profile
  onChange: (next: Profile) => void
  pseudonymError?: string | undefined
}) {
  const ids = { name: useId(), country: useId(), show: useId() }
  const options = useMemo(() => countryOptions(), [])
  return (
    <div className="flex flex-col gap-4">
      <Field
        id={ids.name}
        label={t("network_node_field_pseudonym")}
        optional
        hint={t("network_profile_pseudonym_hint")}
        error={pseudonymError}
      >
        <Input
          id={ids.name}
          name="pseudonym"
          autoComplete="off"
          maxLength={24}
          value={value.pseudonym}
          onChange={(e) => onChange({ ...value, pseudonym: e.target.value })}
          aria-invalid={pseudonymError ? true : undefined}
          aria-describedby={pseudonymError ? `${ids.name}-error` : `${ids.name}-hint`}
        />
      </Field>
      <Field
        id={ids.country}
        label={t("network_node_field_country")}
        optional
        hint={t("network_profile_country_hint")}
      >
        <Select
          value={value.country || NONE}
          onValueChange={(v) =>
            onChange({
              ...value,
              country: v === NONE ? "" : v,
              showCountry: v === NONE ? false : value.showCountry,
            })
          }
        >
          <SelectTrigger id={ids.country} className="w-full">
            <SelectValue placeholder={t("network_profile_no_country")} />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={NONE}>{t("network_profile_no_country")}</SelectItem>
            {options.map((c) => (
              <SelectItem key={c.code} value={c.code}>
                {c.name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </Field>
      <div className="flex items-start gap-3">
        <Switch
          id={ids.show}
          checked={value.showCountry}
          disabled={!value.country}
          onCheckedChange={(v) => onChange({ ...value, showCountry: v })}
          className="mt-0.5"
        />
        <label htmlFor={ids.show} className="text-sm text-fg">
          {t("network_profile_show_country")}
          <span className="block text-xs text-fg-muted">
            {t("network_profile_show_country_hint")}
          </span>
        </label>
      </div>
    </div>
  )
}
