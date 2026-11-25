import {
  Download,
  Globe,
  KeyRound,
  LogOut,
  Plug,
  Radar,
  SquareChevronRight,
  type LucideIcon,
} from "lucide-react"
import { t } from "@/i18n"

/** Icon, label and severity of an event type, for rows that only have a summary. */
export function eventTypeMeta(type: string): { icon: LucideIcon; label: string; severe: boolean } {
  switch (type) {
    case "connect":
      return { icon: Plug, label: t("event_type_connect"), severe: false }
    case "login_attempt":
      return { icon: KeyRound, label: t("event_type_login_attempt"), severe: false }
    case "command":
      return { icon: SquareChevronRight, label: t("event_type_command"), severe: false }
    case "download_attempt":
      return { icon: Download, label: t("event_type_download_attempt"), severe: true }
    case "http_request":
      return { icon: Globe, label: t("event_type_http_request"), severe: false }
    case "disconnect":
      return { icon: LogOut, label: t("event_type_disconnect"), severe: false }
    default:
      return { icon: Radar, label: type === "scan" ? t("event_type_scan") : type, severe: false }
  }
}
