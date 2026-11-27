/**
 * The browser fill helper of the form queue (M38, docs/dev/design/m38.md section 6.3).
 *
 * The kit lives on the dashboard, the form on the provider's site: a page cannot write into
 * another origin, and the dashboard must never be reachable from the provider's page. So the helper
 * is a bookmarklet that carries no data. The owner adds it to the bookmarks bar once. Per kit, the
 * owner copies the kit's fill data (`Kit.fill`, built and checked by the identity guard on the
 * server), opens the form, clicks the bookmark and pastes the data into the small panel it shows.
 * The helper then fills the fields it can match:
 *
 * 1. the CSS selector the shared directory records for a field (when a maintainer read one);
 * 2. the form's own label for a field, from the directory;
 * 3. plain heuristics on the field's label, name, id, placeholder and type: email, name, IP
 *    addresses, abuse type, description, logs, dates.
 *
 * It NEVER submits (N1): no click, no submit, no Enter key. It never touches a captcha, a hidden
 * field, a password, a file input or a check box, and it keeps any value already typed. It outlines
 * every field it filled and shows a banner: "Review and submit yourself".
 *
 * The provider's page can see everything the helper does, so nothing in it names the node or the
 * project (a test checks the source). The data reaches the page only as field values (never as
 * HTML), and a bad selector is ignored.
 */

/** The marker of the fill data (`suckerpot_reporting.forms.FILL_FORMAT`). */
export const FILL_FORMAT = "formfill/1"

/**
 * Runs in the provider's page. Self-contained on purpose: the bookmarklet is this function's own
 * source, so it may not use anything from outside its body (no import, no module constant).
 *
 * With `pasted`, it fills at once (the panel calls it so, and the tests); without, it shows the
 * panel that waits for the owner to paste. Returns the number of fields filled, or -1 when it
 * filled nothing yet (the panel is open, or the data is not fill data).
 */
export function formFill(doc: Document, pasted?: string): number {
  const view = doc.defaultView
  if (!view) return -1
  // The page's own constructors (a page in a frame, or the tests' document, has its own).
  const win = view
  const UI = "data-ff-ui"
  const OUTLINE = "3px solid #d97706"
  const KEYS = [
    "email",
    "name",
    "addresses",
    "abuse_type",
    "first_seen",
    "last_seen",
    "log_excerpt",
    "description",
  ]
  const NAMES: Record<string, string> = {
    email: "email",
    name: "name",
    addresses: "addresses",
    abuse_type: "abuse type",
    first_seen: "first seen",
    last_seen: "last seen",
    log_excerpt: "logs",
    description: "description",
  }
  // Words a form uses for each of our abuse types, most precise first.
  const SYNONYMS: Record<string, string[]> = {
    login_attack: [
      "brute",
      "login",
      "password",
      "credential",
      "ssh",
      "intrusion",
      "hack",
      "attack",
    ],
    exploit: ["exploit", "vulnerab", "intrusion", "hack", "attack", "scan"],
    malware: ["malware", "virus", "trojan", "malicious"],
    c2: ["botnet", "command and control", "c&c", "c2", "malware"],
  }
  const BLOCKED = /captcha|turnstile|cf-chl|g-recaptcha|h-captcha/i
  const TEXT_TYPES = ["", "text", "email", "search", "url", "tel", "date", "datetime-local"]

  const norm = (s: string | null | undefined): string =>
    (s ?? "")
      .toLowerCase()
      .replace(/[_\-.:*()[\]/]+/g, " ")
      .replace(/\s+/g, " ")
      .trim()

  for (const old of Array.from(doc.querySelectorAll(`[${UI}]`))) old.remove()

  function box(): HTMLDivElement {
    const el = doc.createElement("div")
    el.setAttribute(UI, "")
    const s = el.style
    s.position = "fixed"
    s.zIndex = "2147483647"
    s.top = "12px"
    s.right = "12px"
    s.maxWidth = "360px"
    s.padding = "12px 14px"
    s.background = "#fffbeb"
    s.color = "#1c1917"
    s.border = "2px solid #d97706"
    s.borderRadius = "8px"
    s.boxShadow = "0 4px 16px rgba(0,0,0,.25)"
    s.font = "14px/1.4 system-ui, sans-serif"
    return el
  }

  function button(label: string, onClick: () => void): HTMLButtonElement {
    const b = doc.createElement("button")
    b.type = "button"
    b.textContent = label
    b.style.marginTop = "8px"
    b.style.font = "inherit"
    b.addEventListener("click", (e) => {
      e.preventDefault()
      onClick()
    })
    return b
  }

  function parse(raw: string): {
    values: Record<string, string>
    type: string
    labels: Record<string, string>
    selectors: Record<string, string>
  } | null {
    let data: unknown
    try {
      data = JSON.parse(raw.trim())
    } catch {
      return null
    }
    if (!data || typeof data !== "object") return null
    const d = data as Record<string, unknown>
    if (d.format !== "formfill/1" || !d.values || typeof d.values !== "object") return null
    const strings = (o: unknown): Record<string, string> => {
      const out: Record<string, string> = {}
      if (o && typeof o === "object")
        for (const [k, v] of Object.entries(o as Record<string, unknown>))
          if (KEYS.includes(k) && typeof v === "string") out[k] = v
      return out
    }
    return {
      values: strings(d.values),
      type: typeof d.type === "string" ? d.type : "",
      labels: strings(d.labels),
      selectors: strings(d.selectors),
    }
  }

  type Field = HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement

  function usable(el: Element): el is Field {
    if (el.closest(`[${UI}]`)) return false
    if (
      !(el instanceof win.HTMLInputElement) &&
      !(el instanceof win.HTMLTextAreaElement) &&
      !(el instanceof win.HTMLSelectElement)
    )
      return false
    if (el.disabled || el.closest("[hidden]") || el.closest("fieldset[disabled]")) return false
    if (!(el instanceof win.HTMLSelectElement) && el.readOnly) return false
    if (el instanceof win.HTMLInputElement && !TEXT_TYPES.includes(el.type) && el.type !== "radio")
      return false
    for (let p: Element | null = el; p; p = p.parentElement) {
      const st = win.getComputedStyle(p)
      if (st.display === "none" || st.visibility === "hidden") return false
      const tag = `${p.id} ${p.getAttribute("class") ?? ""} ${p.getAttribute("name") ?? ""}`
      if (BLOCKED.test(tag)) return false
    }
    return true
  }

  function labelText(el: Field): string {
    const parts: string[] = []
    const labels: NodeListOf<HTMLLabelElement> | null = el.labels // null for some inputs
    for (const l of labels ? Array.from(labels) : []) parts.push(l.textContent)
    const by = el.getAttribute("aria-labelledby")
    if (by) for (const id of by.split(/\s+/)) parts.push(doc.getElementById(id)?.textContent ?? "")
    parts.push(el.getAttribute("aria-label") ?? "")
    return norm(parts.join(" "))
  }

  function hint(el: Field): string {
    return norm(
      [
        labelText(el),
        el.getAttribute("name"),
        el.id,
        el.getAttribute("placeholder"),
        el.getAttribute("autocomplete"),
        el.getAttribute("title"),
      ].join(" "),
    )
  }

  function setValue(el: Field, value: string): void {
    const proto =
      el instanceof win.HTMLTextAreaElement
        ? win.HTMLTextAreaElement.prototype
        : el instanceof win.HTMLSelectElement
          ? win.HTMLSelectElement.prototype
          : win.HTMLInputElement.prototype
    // The native setter, so a page built with a framework sees the change.
    const desc = Object.getOwnPropertyDescriptor(proto, "value")
    if (desc?.set) desc.set.call(el, value)
    else el.value = value
    el.dispatchEvent(new win.Event("input", { bubbles: true }))
    el.dispatchEvent(new win.Event("change", { bubbles: true }))
  }

  function mark(el: HTMLElement): void {
    el.style.outline = OUTLINE
    el.style.outlineOffset = "2px"
  }

  /** The value for this field, or null when it does not fit (a date field and no date). */
  function shaped(el: Field, key: string, value: string): string | null {
    if (el instanceof win.HTMLInputElement) {
      if (el.type === "date" || el.type === "datetime-local") {
        const m = /^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2})/.exec(value)
        if (!m) return null
        const [, day = "", time = ""] = m
        return el.type === "date" ? day : `${day}T${time}`
      }
      // One line: several addresses become a list on one line.
      value = value
        .split(/\r?\n/)
        .map((l) => l.trim())
        .filter(Boolean)
        .join(key === "addresses" ? ", " : " ")
    }
    if (!(el instanceof win.HTMLSelectElement) && el.maxLength > 0 && value.length > el.maxLength)
      value = value.slice(0, el.maxLength)
    return value
  }

  function pickOption(el: HTMLSelectElement, label: string, type: string): number {
    const options = Array.from(el.options)
    const wanted = norm(label)
    const real = (o: HTMLOptionElement) => !o.disabled && o.value !== ""
    let i = options.findIndex((o) => real(o) && norm(o.textContent) === wanted)
    if (i >= 0) return i
    for (const word of SYNONYMS[type] ?? []) {
      i = options.findIndex((o) => real(o) && norm(o.textContent).includes(word))
      if (i >= 0) return i
    }
    return -1
  }

  function fill(data: NonNullable<ReturnType<typeof parse>>): number {
    const fields = Array.from(doc.querySelectorAll("input, textarea, select")).filter(usable)
    const used = new Set<Element>()
    const filled: string[] = []
    const kept: string[] = []

    const TESTS: Record<string, (el: Field, h: string) => boolean> = {
      email: (el, h) =>
        !(el instanceof win.HTMLSelectElement) &&
        !(el instanceof win.HTMLInputElement && el.type === "radio") &&
        ((el instanceof win.HTMLInputElement && el.type === "email") ||
          /\be ?mail\b|\bemail/.test(h)) &&
        !/abuser|offend|spam|sender|reported|suspect|attacker/.test(h),
      name: (el, h) =>
        el instanceof win.HTMLInputElement &&
        el.type !== "radio" &&
        (/\bname\b|\bfull ?name\b|\bnom\b/.test(h) || el.autocomplete === "name") &&
        !/first|last|given|family|surname|company|organi|user|domain|host|file|server|site|abuser|e ?mail/.test(
          h,
        ),
      addresses: (el, h) =>
        !(el instanceof win.HTMLSelectElement) &&
        !(el instanceof win.HTMLInputElement && (el.type === "radio" || el.type === "email")) &&
        /\bips?\b|\bip ?address|\bipv[46]\b|ip adresse|offending|source address/.test(h),
      abuse_type: (el, h) =>
        (el instanceof win.HTMLSelectElement ||
          (el instanceof win.HTMLInputElement && el.type === "radio")) &&
        /abuse|type|categor|kind|reason|classif|topic|nature/.test(h),
      first_seen: (el, h) =>
        el instanceof win.HTMLInputElement &&
        (el.type === "date" || el.type === "datetime-local") &&
        !/\b(end|last|until|to)\b/.test(h),
      last_seen: (el, h) =>
        el instanceof win.HTMLInputElement &&
        (el.type === "date" || el.type === "datetime-local") &&
        /\b(end|last|until|to)\b/.test(h),
      log_excerpt: (el, h) => el instanceof win.HTMLTextAreaElement && /\blogs?\b|excerpt/.test(h),
      description: (el, h) =>
        el instanceof win.HTMLTextAreaElement &&
        /descr|message|comment|detail|explain|complaint|incident|evidence|information|report|notes?\b|text|body/.test(
          h,
        ),
    }

    function bySelector(key: string): Field[] {
      const sel = data.selectors[key]
      if (!sel) return []
      try {
        return Array.from(doc.querySelectorAll(sel)).filter(usable)
      } catch {
        return [] // not a selector this browser reads: the label and the heuristics remain
      }
    }

    function byLabel(key: string): Field[] {
      const wanted = norm(data.labels[key])
      if (!wanted) return []
      return fields.filter((el) => {
        const l = labelText(el)
        return l === wanted || l.startsWith(`${wanted} `)
      })
    }

    function candidates(key: string): Field[] {
      const found = [...bySelector(key), ...byLabel(key)]
      if (found.length > 0) return found
      const test = TESTS[key]
      return test ? fields.filter((el) => test(el, hint(el))) : []
    }

    function fillRadios(el: HTMLInputElement, label: string): boolean {
      const group = fields.filter(
        (r): r is HTMLInputElement =>
          r instanceof win.HTMLInputElement && r.type === "radio" && r.name === el.name,
      )
      if (group.some((r) => r.checked)) return false
      const wanted = norm(label)
      let hit = group.find((r) => labelText(r) === wanted || norm(r.value) === wanted)
      for (const word of SYNONYMS[data.type] ?? []) {
        if (hit) break
        hit = group.find((r) => labelText(r).includes(word))
      }
      if (!hit) return false
      const setter = Object.getOwnPropertyDescriptor(win.HTMLInputElement.prototype, "checked")
      if (setter?.set) setter.set.call(hit, true)
      else hit.checked = true
      hit.dispatchEvent(new win.Event("input", { bubbles: true }))
      hit.dispatchEvent(new win.Event("change", { bubbles: true }))
      mark(hit)
      for (const r of group) used.add(r)
      return true
    }

    for (const key of KEYS) {
      const value = data.values[key]
      if (!value) continue
      let done = false
      for (const el of candidates(key)) {
        if (used.has(el)) continue
        if (el instanceof win.HTMLInputElement && el.type === "radio") {
          if (key === "abuse_type" && fillRadios(el, value)) done = true
          if (done) break
          continue
        }
        if (el instanceof win.HTMLSelectElement) {
          if (key !== "abuse_type") continue
          const i = pickOption(el, value, data.type)
          if (i < 0) continue
          const option = el.options.item(i)
          if (!option) continue
          if (el.selectedIndex > 0 && el.options.item(el.selectedIndex)?.value) {
            used.add(el) // the owner chose already: never changed
            if (!done) kept.push(key)
            done = true
            break
          }
          setValue(el, option.value)
        } else {
          if (el.value.trim() !== "") {
            used.add(el) // the owner typed something: never overwritten
            if (!done) kept.push(key)
            done = true
            break
          }
          const v = shaped(el, key, value)
          if (v === null) continue
          setValue(el, v)
        }
        used.add(el)
        mark(el)
        done = true
        // A second email field is the "confirm your email" field of the same form.
        if (key !== "email") break
      }
      if (done && !kept.includes(key)) filled.push(key)
    }

    // No field called a description: a form with one free text box takes it there.
    if (
      data.values.description &&
      !filled.includes("description") &&
      !kept.includes("description")
    ) {
      const boxes = fields.filter(
        (el): el is HTMLTextAreaElement =>
          el instanceof win.HTMLTextAreaElement && !used.has(el) && el.value.trim() === "",
      )
      const only = boxes.length === 1 ? boxes[0] : undefined
      const v = only ? shaped(only, "description", data.values.description) : null
      if (only && v !== null) {
        setValue(only, v)
        used.add(only)
        mark(only)
        filled.push("description")
      }
    }

    const banner = box()
    banner.setAttribute("role", "status")
    const title = doc.createElement("strong")
    title.textContent = "Review and submit yourself."
    title.style.display = "block"
    const text = doc.createElement("div")
    const missing = KEYS.filter(
      (k) => data.values[k] && !filled.includes(k) && !kept.includes(k),
    ).map((k) => NAMES[k])
    text.textContent =
      `${filled.length} field${filled.length === 1 ? "" : "s"} filled and outlined. ` +
      "Nothing was submitted. Check every field, the captcha and the consent boxes yourself." +
      (kept.length > 0
        ? ` Kept what was already typed: ${kept.map((k) => NAMES[k]).join(", ")}.`
        : "") +
      (missing.length > 0 ? ` Not found, paste it by hand: ${missing.join(", ")}.` : "")
    banner.append(
      title,
      text,
      button("Close", () => banner.remove()),
    )
    doc.body.append(banner)
    return filled.length
  }

  if (pasted !== undefined) {
    const data = parse(pasted)
    return data ? fill(data) : -1
  }

  const panel = box()
  panel.setAttribute("role", "dialog")
  panel.setAttribute("aria-label", "Fill this form")
  const head = doc.createElement("strong")
  head.textContent = "Fill this form"
  head.style.display = "block"
  const help = doc.createElement("div")
  help.textContent =
    "Paste the fill data you copied from the kit. Fields are filled, nothing is submitted."
  const area = doc.createElement("textarea")
  area.setAttribute("aria-label", "Fill data")
  area.rows = 3
  area.style.width = "100%"
  area.style.marginTop = "8px"
  area.style.font = "12px monospace"
  const note = doc.createElement("div")
  note.setAttribute("role", "alert")
  const tryFill = () => {
    const data = parse(area.value)
    if (!data) {
      if (area.value.trim()) note.textContent = "This is not the fill data of a kit."
      return
    }
    panel.remove()
    fill(data)
  }
  area.addEventListener("input", tryFill)
  panel.append(
    head,
    help,
    area,
    note,
    button("Cancel", () => panel.remove()),
  )
  doc.body.append(panel)
  area.focus()
  return -1
}

/**
 * The bookmarklet: `formFill`'s own source, run on the page where it is clicked. It holds no kit
 * data; the owner pastes that in the panel it opens.
 */
export function bookmarkletHref(): string {
  return `javascript:${encodeURIComponent(`(${formFill.toString()})(document);void 0`)}`
}
