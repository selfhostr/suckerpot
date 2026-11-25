import { render } from "@testing-library/react"
import { afterEach, describe, expect, it, vi } from "vitest"
import { AnimatedNumber } from "./animated-number"

function shown(container: HTMLElement) {
  return container.querySelector("[aria-hidden]")?.textContent
}

describe("AnimatedNumber", () => {
  afterEach(() => vi.restoreAllMocks())

  it("shows the first value at once, and the final value to screen readers", () => {
    const { container } = render(<AnimatedNumber value={1234} />)
    expect(shown(container)).toBe("1,234")
    expect(container.querySelector(".sr-only")?.textContent).toBe("1,234")
  })

  it("jumps to a new value under reduced motion", () => {
    vi.spyOn(window, "matchMedia").mockImplementation(
      (query: string) =>
        ({
          matches: query.includes("reduce"),
          media: query,
          addEventListener: () => undefined,
          removeEventListener: () => undefined,
        }) as unknown as MediaQueryList,
    )
    const { container, rerender } = render(<AnimatedNumber value={10} />)
    rerender(<AnimatedNumber value={500} />)
    expect(shown(container)).toBe("500")
  })
})
