import { afterEach, describe, expect, it, vi } from "vitest"
import { bookmarkletHref, FILL_FORMAT, formFill } from "./form-fill"

const DATA = {
  format: FILL_FORMAT,
  type: "login_attack",
  values: {
    email: "reports@example.org",
    name: "A. Volunteer",
    abuse_type: "Login attack",
    addresses: "198.51.100.23\n198.51.100.24",
    first_seen: "2026-11-16T10:00Z",
    last_seen: "2026-11-20T10:00Z",
    description: "198.51.100.23 (AS64500)\nref 0123456789ab",
    log_excerpt: "2026-11-20T10:00Z 198.51.100.23:41022 TCP/22 (ssh) Login attempts: 412",
  },
}

/** A provider form; its submit handler and buttons record anything that would send it. */
function page(html: string): { form: HTMLFormElement; sent: string[] } {
  document.body.innerHTML = `<form id="f">${html}<button type="submit">Send</button></form>`
  const form = document.getElementById("f") as HTMLFormElement
  const sent: string[] = []
  form.addEventListener("submit", (e) => {
    e.preventDefault()
    sent.push("submit")
  })
  for (const b of Array.from(document.querySelectorAll("button")))
    b.addEventListener("click", () => sent.push("click"))
  vi.spyOn(form, "submit").mockImplementation(() => sent.push("form.submit"))
  vi.spyOn(form, "requestSubmit").mockImplementation(() => sent.push("requestSubmit"))
  return { form, sent }
}

/** The input a selector names (the test fails when there is none). */
function input(selector: string): HTMLInputElement {
  const found = document.querySelector(selector)
  if (!(found instanceof HTMLInputElement)) throw new Error(`no input matches ${selector}`)
  return found
}

/** The text area a selector names (the test fails when there is none). */
function textArea(selector: string): HTMLTextAreaElement {
  const found = document.querySelector(selector)
  if (!(found instanceof HTMLTextAreaElement)) throw new Error(`no text area matches ${selector}`)
  return found
}

const field = input

afterEach(() => {
  document.body.innerHTML = ""
  vi.restoreAllMocks()
})

describe("formFill", () => {
  it("fills the usual fields by their labels and names, and never submits", () => {
    const { sent } = page(`
      <label for="em">Your e-mail address</label><input id="em" type="email" name="contact">
      <label>Full name <input name="reporter_name"></label>
      <label for="ip">Offending IP address(es)</label><input id="ip" name="ip_address">
      <label for="t">Type of abuse</label>
      <select id="t" name="category">
        <option value="">Choose</option><option value="spam">Spam</option>
        <option value="bf">Brute force / login attempts</option>
      </select>
      <label for="d">Describe the incident</label><textarea id="d" name="message"></textarea>
    `)
    const n = formFill(document, JSON.stringify(DATA))
    expect(n).toBe(5)
    expect(field("#em").value).toBe("reports@example.org")
    expect(field("[name=reporter_name]").value).toBe("A. Volunteer")
    // A single-line field gets the addresses on one line.
    expect(field("#ip").value).toBe("198.51.100.23, 198.51.100.24")
    expect((document.getElementById("t") as HTMLSelectElement).value).toBe("bf")
    expect((document.getElementById("d") as HTMLTextAreaElement).value).toBe(
      DATA.values.description,
    )
    expect(field("#em").style.outline).toContain("solid")
    expect(sent).toEqual([])
    const banner = document.querySelector("[role=status]")
    expect(banner?.textContent).toContain("Review and submit yourself.")
    expect(banner?.textContent).toContain("Nothing was submitted")
  })

  it("tells a framework-driven page about each value it sets", () => {
    page(`<label for="em">Email</label><input id="em" type="email">`)
    const seen: string[] = []
    field("#em").addEventListener("input", () => seen.push("input"))
    field("#em").addEventListener("change", () => seen.push("change"))
    formFill(document, JSON.stringify(DATA))
    expect(seen).toEqual(["input", "change"])
  })

  it("uses the directory's selector first, then the form's own label", () => {
    page(`
      <input id="a" name="email">
      <input id="b" name="other">
      <label for="c">Abuse details</label><textarea id="c" name="x1"></textarea>
      <textarea id="d" name="message"></textarea>
    `)
    const data = {
      ...DATA,
      selectors: { email: "#b" },
      labels: { description: "Abuse details" },
    }
    formFill(document, JSON.stringify(data))
    expect(field("#b").value).toBe("reports@example.org")
    expect(field("#a").value).toBe("")
    expect((document.getElementById("c") as HTMLTextAreaElement).value).toBe(
      DATA.values.description,
    )
    expect((document.getElementById("d") as HTMLTextAreaElement).value).toBe("")
  })

  it("ignores a selector the browser cannot read and falls back to the heuristics", () => {
    page(`<input type="email" id="e">`)
    formFill(document, JSON.stringify({ ...DATA, selectors: { email: "[[nope" } }))
    expect(field("#e").value).toBe("reports@example.org")
  })

  it("never touches a captcha, a hidden field, a password, a file or a check box", () => {
    page(`
      <div class="g-recaptcha"><textarea name="g-recaptcha-response"></textarea></div>
      <input type="hidden" name="email">
      <input type="password" name="email_password">
      <input type="file" name="evidence_logs">
      <label><input type="checkbox" name="consent_email"> I agree</label>
      <div style="display:none"><input name="ip"></div>
    `)
    const n = formFill(document, JSON.stringify(DATA))
    expect(n).toBe(0)
    expect(textArea("[name=g-recaptcha-response]").value).toBe("")
    expect(field("[type=hidden]").value).toBe("")
    expect(field("[type=checkbox]").checked).toBe(false)
    expect(field("[style] input, div[style] input").value).toBe("")
    expect(document.querySelector("[role=status]")?.textContent).toContain(
      "Not found, paste it by hand",
    )
  })

  it("keeps what the owner already typed", () => {
    page(`<label for="d">Message</label><textarea id="d">my own words</textarea>`)
    formFill(document, JSON.stringify(DATA))
    expect((document.getElementById("d") as HTMLTextAreaElement).value).toBe("my own words")
    expect(document.querySelector("[role=status]")?.textContent).toContain(
      "Kept what was already typed: description",
    )
  })

  it("puts the logs in a logs box and the description in the only other free text box", () => {
    page(`
      <label for="l">Logs</label><textarea id="l"></textarea>
      <label for="o">Anything else?</label><textarea id="o"></textarea>
    `)
    formFill(document, JSON.stringify(DATA))
    expect((document.getElementById("l") as HTMLTextAreaElement).value).toBe(
      DATA.values.log_excerpt,
    )
    expect((document.getElementById("o") as HTMLTextAreaElement).value).toBe(
      DATA.values.description,
    )
  })

  it("picks an abuse type radio and a date", () => {
    page(`
      <fieldset><legend>Category</legend>
        <label><input type="radio" name="abuse_type" value="1"> Spam</label>
        <label><input type="radio" name="abuse_type" value="2"> Hacking / intrusion</label>
      </fieldset>
      <label for="when">Date of the incident</label><input id="when" type="date">
    `)
    formFill(document, JSON.stringify(DATA))
    const checked = input("input[type=radio]:checked")
    expect(checked.value).toBe("2")
    expect(field("#when").value).toBe("2026-11-16")
  })

  it("respects a field's length limit", () => {
    page(`<label for="d">Description</label><textarea id="d" maxlength="10"></textarea>`)
    formFill(document, JSON.stringify(DATA))
    expect((document.getElementById("d") as HTMLTextAreaElement).value).toHaveLength(10)
  })

  it("refuses anything that is not fill data", () => {
    page(`<input type="email">`)
    expect(formFill(document, "not json")).toBe(-1)
    expect(formFill(document, JSON.stringify({ format: "other", values: {} }))).toBe(-1)
    expect(field("input").value).toBe("")
  })

  it("never writes the data as HTML", () => {
    page(`<label for="d">Message</label><textarea id="d"></textarea>`)
    const evil = { ...DATA, values: { description: "<img src=x onerror=alert(1)>" } }
    formFill(document, JSON.stringify(evil))
    expect(document.querySelector("img")).toBeNull()
    expect((document.getElementById("d") as HTMLTextAreaElement).value).toBe(
      evil.values.description,
    )
  })

  it("opens a panel without data and fills once the data is pasted", () => {
    const { sent } = page(`<label for="em">Email</label><input id="em" type="email">`)
    expect(formFill(document)).toBe(-1)
    const area = textArea("[role=dialog] textarea")
    expect(area).not.toBeNull()
    area.value = "garbage"
    area.dispatchEvent(new Event("input", { bubbles: true }))
    expect(document.querySelector("[role=dialog] [role=alert]")?.textContent).toMatch(
      /not the fill/,
    )
    expect(field("#em").value).toBe("")
    area.value = JSON.stringify(DATA)
    area.dispatchEvent(new Event("input", { bubbles: true }))
    expect(document.querySelector("[role=dialog]")).toBeNull()
    expect(field("#em").value).toBe("reports@example.org")
    expect(sent).toEqual([])
  })
})

describe("bookmarkletHref", () => {
  const source = () => decodeURIComponent(bookmarkletHref().slice("javascript:".length))

  it("is the helper itself and runs on its own", () => {
    page(`<label for="em">Email</label><input id="em" type="email">`)
    // The bookmarklet as a browser runs it: no import, no module scope.
    // eslint-disable-next-line @typescript-eslint/no-implied-eval -- runs the generated bookmarklet
    const run = new Function("document", source()) as (doc: Document) => void
    run(document)
    const area = textArea("[role=dialog] textarea")
    area.value = JSON.stringify(DATA)
    area.dispatchEvent(new Event("input", { bubbles: true }))
    expect(field("#em").value).toBe("reports@example.org")
  })

  it("names neither the node nor the project, and never submits", () => {
    const code = source().toLowerCase()
    for (const word of ["suckerpot", "selfhostr", "honeypot", "honey pot", "/api/"])
      expect(code).not.toContain(word)
    for (const call of [".submit(", "requestsubmit", ".click(", "keydown", "keypress"])
      expect(code).not.toContain(call)
    expect(code).not.toContain("innerhtml")
  })
})
