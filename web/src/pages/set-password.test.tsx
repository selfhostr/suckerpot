import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { render, screen } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { createMemoryRouter, RouterProvider } from "react-router"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { AuthProvider, RequireAuth } from "@/app/auth"
import { ThemeProvider } from "@/app/theme"
import { LoginPage } from "@/pages/login"
import { SetPasswordPage } from "@/pages/set-password"

const json = (status: number, body?: unknown) =>
  new Response(body === undefined ? null : JSON.stringify(body), { status })

const ME = {
  username: "colleague",
  display_name: "A Colleague",
  role: "viewer",
  is_owner: false,
  must_change_password: true,
  read_only: true,
  last_login_at: null,
}

function setup(initial: string) {
  const router = createMemoryRouter(
    [
      { path: "/login", element: <LoginPage /> },
      { path: "/set-password", element: <SetPasswordPage /> },
      {
        element: <RequireAuth />,
        children: [
          { path: "/attacks", element: <h1>Attacks page</h1> },
          { path: "/", element: <h1>Today page</h1> },
        ],
      },
    ],
    { initialEntries: [initial] },
  )
  render(
    <ThemeProvider>
      <QueryClientProvider client={new QueryClient()}>
        <AuthProvider>
          <RouterProvider router={router} />
        </AuthProvider>
      </QueryClientProvider>
    </ThemeProvider>,
  )
  return router
}

describe("first sign-in", () => {
  let mustChange = true
  const bodies: unknown[] = []
  beforeEach(() => {
    mustChange = true
    bodies.length = 0
    vi.stubGlobal(
      "fetch",
      vi.fn((url: string, init?: RequestInit) => {
        if (url.endsWith("/auth/me")) return json(200, { ...ME, must_change_password: mustChange })
        if (url.endsWith("/auth/csrf")) return json(200, { token: "t" })
        if (url.endsWith("/auth/password")) {
          const body = JSON.parse(typeof init?.body === "string" ? init.body : "{}") as {
            current_password: string
          }
          bodies.push(body)
          if (body.current_password === "wrong")
            return json(403, { detail: "no", code: "reauth_failed" })
          mustChange = false
          return json(204)
        }
        return json(404)
      }),
    )
  })
  afterEach(() => vi.unstubAllGlobals())

  it("holds a new account on the Set your password screen, whatever page it asked for", async () => {
    const router = setup("/attacks")
    await screen.findByRole("heading", { name: "Set your password" })
    expect(router.state.location.pathname).toBe("/set-password")
    expect(screen.queryByRole("heading", { name: "Attacks page" })).toBeNull()
    expect(screen.getByLabelText("Temporary password")).toBeInTheDocument()
  })

  it("checks the new password before sending anything", async () => {
    const ui = userEvent.setup()
    setup("/attacks")
    await ui.type(await screen.findByLabelText("Temporary password"), "temp-password-1")
    await ui.type(screen.getByLabelText("New password"), "short")
    await ui.click(screen.getByRole("button", { name: "Save and continue" }))
    expect(screen.getByText("Use at least 12 characters.")).toBeInTheDocument()
    await ui.clear(screen.getByLabelText("New password"))
    await ui.type(screen.getByLabelText("New password"), "a long passphrase 2026")
    await ui.type(screen.getByLabelText("Repeat the new password"), "a different passphrase")
    await ui.click(screen.getByRole("button", { name: "Save and continue" }))
    expect(screen.getByText("The two passwords do not match.")).toBeInTheDocument()
    expect(bodies).toHaveLength(0)
  })

  it("reports a wrong temporary password and then lets the user in", async () => {
    const ui = userEvent.setup()
    const router = setup("/attacks")
    const fill = async (current: string) => {
      await ui.clear(screen.getByLabelText("Temporary password"))
      await ui.type(screen.getByLabelText("Temporary password"), current)
      await ui.clear(screen.getByLabelText("New password"))
      await ui.type(screen.getByLabelText("New password"), "a long passphrase 2026")
      await ui.clear(screen.getByLabelText("Repeat the new password"))
      await ui.type(screen.getByLabelText("Repeat the new password"), "a long passphrase 2026")
      await ui.click(screen.getByRole("button", { name: "Save and continue" }))
    }
    await screen.findByLabelText("Temporary password")
    await fill("wrong")
    expect(await screen.findByText("That password is not correct.")).toBeInTheDocument()
    await fill("temp-password-1")
    await screen.findByRole("heading", { name: "Today page" })
    expect(router.state.location.pathname).toBe("/")
    expect(bodies.at(-1)).toEqual({
      current_password: "temp-password-1",
      new_password: "a long passphrase 2026",
    })
  })

  it("sends an account that already chose a password straight on", async () => {
    mustChange = false
    const router = setup("/set-password")
    await screen.findByRole("heading", { name: "Today page" })
    expect(router.state.location.pathname).toBe("/")
  })
})
