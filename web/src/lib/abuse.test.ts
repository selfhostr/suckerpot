import { describe, expect, it } from "vitest"
import {
  blockedReason,
  blockedReasons,
  describeAbuseError,
  describeBlockedDrafts,
  describeBlockedRow,
  describeGuard,
  describeReports,
  describeSettingsIssue,
  guardAdvice,
  guardReason,
  guardReasonsOf,
  nextActions,
  reviewBlocker,
  settingsIssuesOf,
  type AbuseStatus,
  type ReportDetail,
} from "./abuse"
import { ApiError } from "./api"

const status = (over: Partial<AbuseStatus> = {}): AbuseStatus => ({
  enabled: true,
  gate: "open",
  rdap_quota: { used: 0, limit: 1000 },
  self_address_known: true,
  self_address_fresh: true,
  counts: { draft: 4, reviewed: 0, sent: 0, closed: 0, discarded: 0, superseded: 0 },
  waiting_for_contact: 0,
  ...over,
})

describe("describeReports", () => {
  it("says how many reports are ready", () => {
    expect(describeReports(status())).toBe("4 drafts to review.")
  })
  it("counts the same things as the tabs", () => {
    expect(describeReports(status(), { toSend: 3, replies: 2 })).toBe(
      "4 drafts to review, 3 reports ready to send, 2 replies to check.",
    )
  })
  it("says when there is nothing to report", () => {
    const s = status({ counts: { ...status().counts, draft: 0 } })
    expect(describeReports(s)).toBe(
      "Nothing to report: no source crossed the thresholds this week.",
    )
  })
})

describe("blockedReason", () => {
  it("explains a missing self address first", () => {
    expect(blockedReason(status({ self_address_known: false }))).toMatch(/not known yet/)
  })
  it("warns when the learned address is stale", () => {
    expect(blockedReason(status({ self_address_fresh: false }))).toMatch(/fresh one/)
  })
  it("points to the settings when the reply contact is missing", () => {
    expect(describeAbuseError(new ApiError(409, "x", "settings_incomplete"))).toBe(
      "Set the reply contact in the Reporting settings first",
    )
  })
  it("is null when everything works", () => {
    expect(blockedReason(status())).toBeNull()
  })
})

describe("identity check wording", () => {
  it("counts what was masked and removed", () => {
    expect(describeGuard({ ok: true, codes: [] }, { masked: 2, removed: 1 })).toBe(
      "Nothing identifying found. 2 addresses masked, 1 line removed.",
    )
  })
  it("explains reason codes in plain English and never shows a value", () => {
    expect(guardReason("project_term")).toMatch(/name of this project/)
    expect(guardReason("something_new")).toMatch(/refused/)
  })
  it("reads the reasons of a blocked answer", () => {
    const e = new ApiError(409, "x", "identity_guard_failed", { reasons: ["self_name"] })
    expect(guardReasonsOf(e)).toEqual(["self_name"])
    expect(guardReasonsOf(new Error("x"))).toBeNull()
  })
})

describe("review rules", () => {
  const base = {
    guard: { ok: true, codes: [] },
    recipient: { mailbox: "abuse@example.net" },
    missing: [],
  } as unknown as ReportDetail
  it("needs a reply contact, and no wording", () => {
    expect(reviewBlocker({ ...base, missing: ["reply_contact"] })).toMatch(/reply contact/)
    expect(reviewBlocker(base)).toBeNull()
  })
  it("is blocked by a failed identity check", () => {
    expect(reviewBlocker({ ...base, guard: { ok: false, codes: ["self_name"] } })).toMatch(
      /blocked/,
    )
  })
  it("follows the workflow", () => {
    expect(nextActions("draft")).toEqual(["reviewed", "discarded"])
    expect(nextActions("sent")).toEqual(["closed"])
    expect(nextActions("closed")).toEqual([])
  })
  it("explains a revision conflict", () => {
    expect(describeAbuseError(new ApiError(409, "x", "revision_mismatch"))).toMatch(/changed/)
  })
})

/** Every code the guard and the draft builder can store (api/abuse_core.py, reporting guard). */
const STORED_CODES = [
  "self_address",
  "self_name",
  "owner_domain",
  "vpn_address",
  "project_term",
  "private_address",
  "documentation_address",
  "dashboard_path",
  "internal_id",
  "default_wording",
  "no_self_address",
  "self_terms_unavailable",
  "settings_incomplete",
  "evidence_invalid",
  "eml_invalid_recipient",
  "bad_reply_token",
]

describe("why a draft is blocked", () => {
  it("has a sentence and a next step for every stored code, never the raw code", () => {
    for (const code of STORED_CODES) {
      const { why, fix } = guardAdvice(code)
      expect(why, code).not.toMatch(/refused/)
      expect(why.length, code).toBeGreaterThan(20)
      expect(fix.length, code).toBeGreaterThan(20)
      expect(`${why} ${fix}`, code).not.toContain(code)
      expect(describeBlockedRow({ ok: false, codes: [code] }), code).not.toContain(code)
    }
  })
  it("falls back to a safe sentence for a code it does not know", () => {
    expect(guardAdvice("something_new")).toEqual({
      why: "The identity check refused this text.",
      fix: "Regenerate the draft, or discard it.",
    })
  })
  it("says why in a few words on a row, and nothing on a clean one", () => {
    expect(describeBlockedRow({ ok: true, codes: [] })).toBeNull()
    expect(describeBlockedRow({ ok: false, codes: ["project_term"] })).toBe(
      "Why: names the project",
    )
    expect(
      describeBlockedRow({ ok: false, codes: ["self_name", "project_term", "default_wording"] }),
    ).toBe("Why: names your system, names the project and 1 more")
  })
  it("counts the blocked drafts and orders the reasons by size", () => {
    const blocked = {
      count: 181,
      reasons: { default_wording: 121, project_term: 181, self_name: 181 },
    }
    expect(describeBlockedDrafts(blocked)).toBe(
      "181 drafts are blocked by the identity check: they cannot be reviewed, copied or sent until the cause is fixed.",
    )
    expect(describeBlockedDrafts({ count: 1, reasons: {} })).toMatch(
      /^1 draft is blocked.*: it cannot/,
    )
    expect(blockedReasons(blocked).map((r) => [r.code, r.drafts])).toEqual([
      ["project_term", 181],
      ["self_name", 181],
      ["default_wording", 121],
    ])
  })
})

describe("settings that block every report", () => {
  it("says field by field what to change, in one sentence", () => {
    expect(describeSettingsIssue("reply_contact", ["project_term"])).toBe(
      "This reply address names the project, so every report would reveal the honeypot. Use a neutral address.",
    )
    expect(describeSettingsIssue("signature", ["default_wording"])).toBe(
      "The signature uses wording that older versions shipped as a default, so every report could be recognised. Reword it, or leave it empty.",
    )
  })
  it("names every reason of one field once", () => {
    const text = describeSettingsIssue("reply_contact", ["project_term", "self_name"])
    expect(text).toMatch(
      /^This reply address names the project.*It also names your monitored system/,
    )
    expect(text.match(/Use a neutral address\./g)).toHaveLength(1)
  })
  it("never prints a raw code, even for an unknown one", () => {
    expect(describeSettingsIssue("intro", ["brand_new_code"])).toBe(
      "The introduction would be refused by the identity check, so every report is blocked. Reword it, or leave it empty.",
    )
  })
  it("reads the fields of a refused save", () => {
    const e = new ApiError(409, "x", "identity_guard_failed", {
      reasons: ["project_term"],
      fields: { reply_contact: ["project_term"], intro: ["default_wording"] },
    })
    expect(settingsIssuesOf(e)).toEqual({
      reply_contact: ["project_term"],
      intro: ["default_wording"],
    })
    // A refusal without fields (a render, a download) or any other error is not a settings one.
    expect(
      settingsIssuesOf(new ApiError(409, "x", "identity_guard_failed", { reasons: [] })),
    ).toBeNull()
    expect(settingsIssuesOf(new ApiError(409, "x", "revision_mismatch"))).toBeNull()
    expect(settingsIssuesOf(new Error("x"))).toBeNull()
  })
})
