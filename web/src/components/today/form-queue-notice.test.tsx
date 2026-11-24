import { render, screen } from "@testing-library/react"
import { MemoryRouter } from "react-router"
import { describe, expect, it } from "vitest"
import { formQueueSentence, type FormQueueCount } from "@/lib/today"
import { FormQueueNotice } from "./form-queue-notice"

function mount(count: FormQueueCount | null | undefined) {
  return render(
    <MemoryRouter>
      <FormQueueNotice count={count} />
    </MemoryRouter>,
  )
}

describe("FormQueueNotice", () => {
  it("says how many reports wait and links to the queue", () => {
    mount({ reports: 3, providers: 2 })
    const region = screen.getByRole("region", { name: "Reports to submit by web form" })
    expect(region).toHaveTextContent("3 reports to submit by web form, for 2 providers.")
    expect(screen.getByRole("link", { name: /Open the form queue/ })).toHaveAttribute(
      "href",
      "/abuse?status=forms",
    )
  })

  it("is hidden when nothing waits, or for a viewer who gets no count", () => {
    for (const count of [null, undefined, { reports: 0, providers: 0 }]) {
      const { container, unmount } = mount(count)
      expect(container).toBeEmptyDOMElement()
      unmount()
    }
  })
})

describe("formQueueSentence", () => {
  it("speaks in singular and plural, with a thousands separator", () => {
    expect(formQueueSentence({ reports: 1, providers: 1 })).toBe(
      "1 report to submit by web form, for 1 provider",
    )
    expect(formQueueSentence({ reports: 1200, providers: 4 })).toBe(
      "1,200 reports to submit by web form, for 4 providers",
    )
  })
})
