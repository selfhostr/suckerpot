import { act, render, screen } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { afterEach, describe, expect, it, vi } from "vitest"
import { LoadMore } from "./load-more"

type Callback = (entries: { isIntersecting: boolean }[]) => void

afterEach(() => vi.unstubAllGlobals())

describe("LoadMore", () => {
  it("renders nothing when there is no next page", () => {
    const { container } = render(
      <LoadMore
        hasNextPage={false}
        isFetchingNextPage={false}
        fetchNextPage={vi.fn()}
        label="More"
      />,
    )
    expect(container).toBeEmptyDOMElement()
  })

  it("stays a working button for keyboard users", async () => {
    const fetchNextPage = vi.fn()
    render(
      <LoadMore
        hasNextPage
        isFetchingNextPage={false}
        fetchNextPage={fetchNextPage}
        label="More"
      />,
    )
    await userEvent.click(screen.getByRole("button", { name: "More" }))
    expect(fetchNextPage).toHaveBeenCalledOnce()
  })

  it("loads the next page by itself once it nears the viewport", () => {
    let cb: Callback = () => undefined
    vi.stubGlobal(
      "IntersectionObserver",
      class {
        constructor(c: Callback) {
          cb = c
        }
        observe = () => undefined
        disconnect = () => undefined
      },
    )
    const fetchNextPage = vi.fn()
    render(
      <LoadMore
        hasNextPage
        isFetchingNextPage={false}
        fetchNextPage={fetchNextPage}
        label="More"
      />,
    )
    expect(fetchNextPage).not.toHaveBeenCalled()
    act(() => cb([{ isIntersecting: true }]))
    expect(fetchNextPage).toHaveBeenCalledOnce()
  })

  it("is disabled while a page is loading", () => {
    render(<LoadMore hasNextPage isFetchingNextPage fetchNextPage={vi.fn()} label="More" />)
    expect(screen.getByRole("button", { name: "Loading…" })).toBeDisabled()
  })
})
