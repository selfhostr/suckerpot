import { describe, expect, it } from "vitest"
import { isSevereEvent, tagSeverity } from "./severity"

describe("tag severity", () => {
  it("marks payload and exploit tags severe, harmful ones warning, the rest neutral", () => {
    for (const t of [
      "container-escape",
      "sql-rce",
      "eternalblue",
      "php2shell",
      "mirai",
      "synology-exploit",
      "c3rb3r",
    ])
      expect(tagSeverity(t)).toBe("severe")
    for (const t of ["db-ransom", "redis-rogue-master", "sip-fraud", "persistence"])
      expect(tagSeverity(t)).toBe("warning")
    for (const t of ["bluekeep", "weak-credentials"]) expect(tagSeverity(t)).toBe("warning")
    expect(tagSeverity("rdp-cleartext")).toBeNull()
    expect(tagSeverity("recon")).toBeNull()
  })
  it("keeps the reconnaissance tags informational: never red, never orange", () => {
    for (const t of ["service-probe", "iot-shell-probe", "env-file-probe", "scanner", "recon"])
      expect(tagSeverity(t)).toBeNull()
    expect(isSevereEvent("command", ["iot-shell-probe"])).toBe(false)
    expect(isSevereEvent("http_request", ["service-probe"])).toBe(false)
  })
  it("reds only the event that carries the exploit", () => {
    expect(isSevereEvent("download_attempt", [])).toBe(true)
    expect(isSevereEvent("http_request", ["php2shell"])).toBe(true)
    expect(isSevereEvent("http_request", ["container-escape"])).toBe(true)
    expect(isSevereEvent("scan", ["eternalblue"])).toBe(true)
    expect(isSevereEvent("command", ["sql-rce"])).toBe(true)
    expect(isSevereEvent("login_attempt", ["sql-rce"])).toBe(false)
    expect(isSevereEvent("command", ["db-ransom"])).toBe(false)
    expect(isSevereEvent("disconnect", ["bluekeep"])).toBe(false)
  })
})
