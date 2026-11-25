import { t } from "@/i18n"

/** What the "hide research scanners" switch does to the numbers, in words. */
export function scannerCaption(hide: boolean, sessions: number | undefined): string {
  if (sessions === undefined) return " "
  if (sessions === 0) return t("scanner_caption_none")
  return hide
    ? t("scanner_caption_hidden", { count: sessions })
    : t("scanner_caption_shown", { count: sessions })
}
