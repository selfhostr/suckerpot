import { describe, expect, it } from "vitest"
import { ApiError } from "./api"
import {
  buildMailto,
  describeQueue,
  describeRequest,
  describeSendError,
  describeSendErrorCode,
  MAILTO_LIMIT,
  queueRefetch,
  SEND_ERROR,
  type QueueItem,
} from "./abuse-send"

describe("buildMailto", () => {
  it("carries recipient, subject and a short body", () => {
    const m = buildMailto("abuse@example.net", "Abuse report & more", "Hello\nWorld")
    expect(m.bodyIncluded).toBe(true)
    expect(m.href.startsWith("mailto:abuse@example.net?subject=Abuse%20report%20%26%20more")).toBe(
      true,
    )
    expect(m.href).toContain("&body=Hello%0D%0AWorld")
  })
  it("drops the body when the whole link would reach the limit", () => {
    const m = buildMailto("abuse@example.net", "Subject", "x".repeat(3000))
    expect(m.bodyIncluded).toBe(false)
    expect(m.href).not.toContain("body=")
    expect(m.href.length).toBeLessThan(MAILTO_LIMIT)
  })
})

describe("sentences", () => {
  it("maps every worker error code to a sentence", () => {
    for (const code of Object.keys(SEND_ERROR)) {
      expect(describeSendErrorCode(code).length).toBeGreaterThan(15)
    }
    expect(describeSendErrorCode("weird")).toBe("The message could not be sent.")
    expect(describeSendErrorCode(null)).toBe("The message could not be sent.")
  })
  it("reads guard failures by prefix and the closed gate", () => {
    expect(describeSendErrorCode("guard_failed:no_self_address")).toMatch(/Settings → Reporting/)
    expect(describeSendErrorCode("guard_failed:project_term")).toBe(
      "Blocked by the identity check.",
    )
    expect(
      describeRequest({ status: "pending", error_code: "egress_closed", done_at: null }),
    ).toMatch(/Waiting for the VPN/)
  })
  it("shows the server's reply code of a refusal and explains a deferral", () => {
    expect(describeSendErrorCode("refused:550")).toBe(
      "The mail server refused the message or the recipient. (server code 550)",
    )
    expect(describeSendErrorCode("refused")).toBe(
      "The mail server refused the message or the recipient.",
    )
    expect(describeSendErrorCode("deferred:451")).toMatch(/try later.*\(server code 451\)$/)
    expect(describeSendErrorCode("refused:<script>")).toBe(
      "The mail server refused the message or the recipient.",
    )
    expect(describeSendErrorCode("nonsense:550")).toBe("The message could not be sent.")
  })
  it("treats sending like pending and explains an unknown outcome", () => {
    expect(describeRequest({ status: "sending", error_code: null, done_at: null })).toBe("Sending…")
    expect(describeSendErrorCode("unknown_outcome")).toMatch(/may or may not have left/)
  })
  it("describes a request", () => {
    expect(describeRequest(null)).toBeNull()
    expect(describeRequest({ status: "pending", error_code: null, done_at: null })).toBe("Sending…")
    expect(describeRequest({ status: "failed", error_code: "auth_failed", done_at: null })).toMatch(
      /^Not sent\. The mail server refused the username/,
    )
    expect(describeRequest({ status: "cancelled", error_code: null, done_at: null })).toMatch(
      /Cancelled/,
    )
  })
  it("maps 409 codes, 422 problems and reauth", () => {
    expect(describeSendError(new ApiError(409, "x", "smtp_off"))).toMatch(/switched off/)
    expect(describeSendError(new ApiError(409, "x", "report_not_ready"))).toMatch(/not ready/)
    expect(describeSendError(new ApiError(409, "x", "already_queued"))).toMatch(/already queued/)
    expect(describeSendError(new ApiError(409, "x", "revision_mismatch"))).toMatch(/changed/)
    expect(describeSendError(new ApiError(409, "x", "nothing_to_cancel"))).toMatch(
      /nothing to cancel/i,
    )
    expect(describeSendError(new ApiError(503, "x", "editing_disabled"))).toMatch(/Encryption key/)
    expect(
      describeSendError(
        new ApiError(422, "x", "identity_guard_failed", { reasons: ["self_name"] }),
      ),
    ).toBe("The sender name or address matches one of your own terms.")
    expect(describeSendError(new ApiError(403, "x", "reauth_failed"))).toBe(
      "That password is not right.",
    )
    expect(
      describeSendError(
        new ApiError(422, "x", "invalid_host", {
          problems: ["invalid_host", "invalid_from_address"],
        }),
      ),
    ).toMatch(/not an address.*not a valid mailbox/)
    expect(describeSendError(new ApiError(422, "x", "something_new"))).toMatch(/not valid/)
    expect(describeSendError(new Error("boom"))).toMatch(/did not work/)
  })
  it("counts the queue", () => {
    expect(describeQueue(0)).toBe("Nothing is waiting to be sent.")
    expect(describeQueue(1)).toBe("1 report is ready to send.")
    expect(describeQueue(12)).toBe("12 reports are ready to send.")
  })
})

describe("queueRefetch", () => {
  const item = (over: Partial<QueueItem>): QueueItem => ({
    id: "a",
    recipient: "abuse@example.net",
    subject: "s",
    body_text: "b",
    scheduled_at: null,
    last_request: null,
    ...over,
  })
  it("polls only while something is on its way", () => {
    expect(queueRefetch(undefined)).toBe(false)
    expect(queueRefetch([item({})])).toBe(false)
    expect(queueRefetch([item({ scheduled_at: "2026-11-01T10:00:00Z" })])).toBe(4000)
    expect(
      queueRefetch([
        item({ last_request: { status: "pending", error_code: null, done_at: null } }),
      ]),
    ).toBe(4000)
  })
})

describe("cancel codes of the desk and the never list", () => {
  it("explains shared_host, form_only and undeliverable", () => {
    expect(describeSendErrorCode("shared_host")).toMatch(/shared service/)
    expect(describeSendErrorCode("form_only")).toMatch(/web form/)
    expect(describeSendErrorCode("undeliverable")).toMatch(/bounced/)
    expect(describeRequest({ status: "cancelled", error_code: "form_only" } as never)).toBe(
      "Cancelled. It will not be sent.",
    )
  })
})
