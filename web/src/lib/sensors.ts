/**
 * The sensor registry: the ONE place that knows which sensors exist, how they
 * are named, grouped, drawn and on which port they listen. Every list, filter,
 * chart, legend and colour in the UI is derived from it.
 *
 * Colour scales by FAMILY, not by sensor: twelve hues would be neither calm nor
 * colour-blind safe, so each family has one hue (tokens.css `--family-*`) and
 * each sensor is told apart by its icon and its label, which are always shown.
 * Per-sensor shades (`--sensor-*`) exist only for the per-sensor chart split.
 */
import {
  Container,
  Database,
  DatabaseZap,
  FolderOpen,
  HardDrive,
  Globe,
  Monitor,
  Phone,
  Router,
  Server,
  Smartphone,
  SquareTerminal,
  type LucideIcon,
} from "lucide-react"
import { intlLocale, t, tk } from "@/i18n"
import { withText } from "./t-getters"

/** Registry order: family by family, busiest-first inside a family. Charts stack in this order. */
export const SENSORS = [
  "ssh",
  "telnet",
  "adb",
  "web",
  "docker",
  "synology",
  "redis",
  "mysql",
  "mssql",
  "rdp",
  "smb",
  "sip",
] as const
export type Sensor = (typeof SENSORS)[number]

export const SENSOR_FAMILIES = ["shell", "web", "data", "windows"] as const
export type SensorFamily = (typeof SENSOR_FAMILIES)[number]

export function isSensor(value: unknown): value is Sensor {
  return typeof value === "string" && (SENSORS as readonly string[]).includes(value)
}

export interface FamilyMeta {
  id: SensorFamily
  /** "Remote shells". */
  label: string
  /** Lower-case form for sentences ("the remote shells"). */
  noun: string
  description: string
  /** Tailwind text colour class (AA as text). */
  text: string
  /** Tailwind background class for solid marks. */
  fill: string
  /** Tinted badge background. */
  tint: string
  /** Raw CSS variable, for SVG fills and inline styles. */
  cssVar: string
  /** Members, in registry order. */
  sensors: readonly Sensor[]
}

export interface SensorMeta {
  id: Sensor
  label: string
  /** Protocol name as written in sentences ("tried 37 SSH passwords"). */
  noun: string
  description: string
  icon: LucideIcon
  family: SensorFamily
  /** Default public port, shown in the filter and the styleguide. */
  port: number
  /** "udp" only for SIP; everything else is TCP. */
  transport: "tcp" | "udp"
  /** What a login attempt is called in a story ("password" or "login"). */
  credential: "password" | "login"
  /** Family text colour class (sensors never carry their own text colour). */
  text: string
  /** Family background class for dots and accents. */
  fill: string
  /** Family tint for badges. */
  tint: string
  /** Family CSS variable. */
  cssVar: string
  /** Per-sensor shade, for the per-sensor chart split only (fill, not text). */
  shadeVar: string
}

const FAMILY_STYLE: Record<SensorFamily, Pick<FamilyMeta, "text" | "fill" | "tint" | "cssVar">> = {
  shell: {
    text: "text-family-shell",
    fill: "bg-family-shell",
    tint: "tint-family-shell",
    cssVar: "var(--family-shell)",
  },
  web: {
    text: "text-family-web",
    fill: "bg-family-web",
    tint: "tint-family-web",
    cssVar: "var(--family-web)",
  },
  data: {
    text: "text-family-data",
    fill: "bg-family-data",
    tint: "tint-family-data",
    cssVar: "var(--family-data)",
  },
  windows: {
    text: "text-family-windows",
    fill: "bg-family-windows",
    tint: "tint-family-windows",
    cssVar: "var(--family-windows)",
  },
}

type SensorDef = Omit<SensorMeta, "id" | "text" | "fill" | "tint" | "cssVar" | "shadeVar">

const DEFS: Record<Sensor, SensorDef> = {
  ssh: {
    label: "SSH",
    noun: "SSH",
    description: tk("sensor_ssh_description"),
    icon: SquareTerminal,
    family: "shell",
    port: 22,
    transport: "tcp",
    credential: "password",
  },
  telnet: {
    label: "Telnet",
    noun: "Telnet",
    description: tk("sensor_telnet_description"),
    icon: Router,
    family: "shell",
    port: 23,
    transport: "tcp",
    credential: "password",
  },
  adb: {
    label: "ADB",
    noun: "ADB",
    description: tk("sensor_adb_description"),
    icon: Smartphone,
    family: "shell",
    port: 5555,
    transport: "tcp",
    credential: "login",
  },
  web: {
    label: tk("sensor_web_label"),
    noun: "HTTP",
    description: tk("sensor_web_description"),
    icon: Globe,
    family: "web",
    port: 80,
    transport: "tcp",
    credential: "login",
  },
  docker: {
    label: "Docker",
    noun: "Docker API",
    description: tk("sensor_docker_description"),
    icon: Container,
    family: "web",
    port: 2375,
    transport: "tcp",
    credential: "login",
  },
  redis: {
    label: "Redis",
    noun: "Redis",
    description: tk("sensor_redis_description"),
    icon: DatabaseZap,
    family: "data",
    port: 6379,
    transport: "tcp",
    credential: "password",
  },
  mysql: {
    label: "MySQL",
    noun: "MySQL",
    description: tk("sensor_mysql_description"),
    icon: Database,
    family: "data",
    port: 3306,
    transport: "tcp",
    credential: "password",
  },
  mssql: {
    label: "MSSQL",
    noun: "SQL Server",
    description: tk("sensor_mssql_description"),
    icon: Server,
    family: "data",
    port: 1433,
    transport: "tcp",
    credential: "password",
  },
  rdp: {
    label: "RDP",
    noun: "RDP",
    description: tk("sensor_rdp_description"),
    icon: Monitor,
    family: "windows",
    port: 3389,
    transport: "tcp",
    credential: "login",
  },
  smb: {
    label: "SMB",
    noun: "SMB",
    description: tk("sensor_smb_description"),
    icon: FolderOpen,
    family: "windows",
    port: 445,
    transport: "tcp",
    credential: "login",
  },
  sip: {
    label: "SIP",
    noun: "SIP",
    description: tk("sensor_sip_description"),
    icon: Phone,
    family: "windows",
    port: 5060,
    transport: "udp",
    credential: "login",
  },
  synology: {
    label: "Synology",
    noun: "Synology NAS",
    description: tk("sensor_synology_description"),
    icon: HardDrive,
    family: "web",
    port: 5000,
    transport: "tcp",
    credential: "password",
  },
}

// Literal class names, so Tailwind sees every one of them.
const SHADE_VAR: Record<Sensor, string> = {
  ssh: "var(--sensor-ssh)",
  telnet: "var(--sensor-telnet)",
  adb: "var(--sensor-adb)",
  web: "var(--sensor-web)",
  docker: "var(--sensor-docker)",
  redis: "var(--sensor-redis)",
  mysql: "var(--sensor-mysql)",
  mssql: "var(--sensor-mssql)",
  rdp: "var(--sensor-rdp)",
  smb: "var(--sensor-smb)",
  sip: "var(--sensor-sip)",
  synology: "var(--sensor-synology)",
}

/** `{ [key]: make(key) }` for a closed list of keys, fully typed. */
function byKey<K extends string, V>(keys: readonly K[], make: (key: K) => V): Record<K, V> {
  const out = {} as Record<K, V>
  for (const k of keys) out[k] = make(k)
  return out
}

/** `label` and `description` read through t() every time, so they follow the language. */
export const SENSOR_META: Record<Sensor, SensorMeta> = byKey(SENSORS, (id) => {
  const def = DEFS[id]
  return withText(
    { id, ...def, ...FAMILY_STYLE[def.family], shadeVar: SHADE_VAR[id] },
    id === "web"
      ? { label: def.label, description: def.description }
      : { description: def.description },
  )
})

const FAMILY_TEXT: Record<SensorFamily, { label: string; noun: string; description: string }> = {
  shell: {
    label: tk("sensor_family_shell_label"),
    noun: tk("sensor_family_shell_noun"),
    description: tk("sensor_family_shell_description"),
  },
  web: {
    label: tk("sensor_family_web_label"),
    noun: tk("sensor_family_web_noun"),
    description: tk("sensor_family_web_description"),
  },
  data: {
    label: tk("sensor_family_data_label"),
    noun: tk("sensor_family_data_noun"),
    description: tk("sensor_family_data_description"),
  },
  windows: {
    label: tk("sensor_family_windows_label"),
    noun: tk("sensor_family_windows_noun"),
    description: tk("sensor_family_windows_description"),
  },
}

/** `label`, `noun` and `description` read through t() every time, so they follow the language. */
export const FAMILY_META: Record<SensorFamily, FamilyMeta> = byKey(SENSOR_FAMILIES, (id) =>
  withText(
    {
      id,
      ...FAMILY_TEXT[id],
      ...FAMILY_STYLE[id],
      sensors: SENSORS.filter((s) => DEFS[s].family === id),
    },
    FAMILY_TEXT[id],
  ),
)

export function sensorMeta(sensor: string): SensorMeta | null {
  return isSensor(sensor) ? SENSOR_META[sensor] : null
}

export function familyOf(sensor: string): SensorFamily | null {
  return isSensor(sensor) ? SENSOR_META[sensor].family : null
}

// --- The `?sensor=` URL filter: a comma-separated list, e.g. `?sensor=ssh,telnet`.

/** Parse `?sensor=`: known names only, deduplicated, in registry order. */
export function parseSensors(raw: string | null | undefined): Sensor[] {
  if (!raw) return []
  const wanted = new Set(raw.split(",").map((s) => s.trim().toLowerCase()))
  return SENSORS.filter((s) => wanted.has(s))
}

/** The `?sensor=` value for a selection; `null` (no filter) when empty or when every sensor is in. */
export function formatSensors(sensors: readonly Sensor[]): string | null {
  const set = new Set(sensors)
  if (set.size === 0 || set.size === SENSORS.length) return null
  return SENSORS.filter((s) => set.has(s)).join(",")
}

/** `/attacks?sensor=ssh,telnet`, or `/attacks` for no filter. */
export function sensorsHref(sensors: readonly Sensor[], path = "/attacks"): string {
  const v = formatSensors(sensors)
  return v ? `${path}?sensor=${v}` : path
}

/** The family whose members are exactly this selection, if any. */
export function exactFamily(sensors: readonly Sensor[]): SensorFamily | null {
  const set = new Set(sensors)
  for (const f of SENSOR_FAMILIES) {
    const members = FAMILY_META[f].sensors
    if (members.length === set.size && members.every((s) => set.has(s))) return f
  }
  return null
}

/** "A, B and C" in the active language ("A, B and C" in English, no Oxford comma). */
export function listAnd(parts: readonly string[]): string {
  if (parts.length <= 1) return parts.join("")
  const locale = intlLocale()
  return new Intl.ListFormat(locale === "en" ? "en-GB" : locale, {
    style: "long",
    type: "conjunction",
  }).format(parts)
}

/** "A, B, C" in the active language (a plain run of clauses, no "and"). */
export function listPlain(parts: readonly string[]): string {
  if (parts.length <= 1) return parts.join("")
  return new Intl.ListFormat(intlLocale(), { style: "long", type: "unit" }).format(parts)
}

/**
 * Human name of a selection: "All sensors", "SSH", "SSH and Telnet",
 * "Remote shells" (a whole family) or "5 sensors".
 */
export function sensorSetLabel(sensors: readonly Sensor[]): string {
  if (sensors.length === 0 || sensors.length === SENSORS.length) return t("sensors_set_all")
  const family = sensors.length > 1 ? exactFamily(sensors) : null
  if (family) return FAMILY_META[family].label
  if (sensors.length <= 3) return listAnd(sensors.map((s) => SENSOR_META[s].label))
  return t("sensors_set_count", { count: sensors.length })
}

/** The same, for the middle of a sentence: "SSH and Telnet", "the remote shells", "5 sensors". */
export function sensorSetPhrase(sensors: readonly Sensor[]): string {
  if (sensors.length === 0 || sensors.length === SENSORS.length) return t("sensors_phrase_all")
  const family = sensors.length > 1 ? exactFamily(sensors) : null
  if (family) return t("sensors_phrase_family", { noun: FAMILY_META[family].noun })
  return sensorSetLabel(sensors)
}

/** Sum a per-sensor record into per-family totals. */
export function sumByFamily(
  bySensor: Partial<Record<string, number>>,
): Record<SensorFamily, number> {
  const out = { shell: 0, web: 0, data: 0, windows: 0 } satisfies Record<SensorFamily, number>
  for (const s of SENSORS) out[SENSOR_META[s].family] += bySensor[s] ?? 0
  return out
}
