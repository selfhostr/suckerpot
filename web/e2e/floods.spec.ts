import { expect, test, type Page } from "@playwright/test"
import { h1, settle, shoot, shootTall } from "./helpers"

// Flood groups: one row for the hundreds of plain connections one address opens in an hour.

const groupTitle = (page: Page) =>
  page.getByRole("heading", { level: 1, name: /opened 812 RDP connections/ })

test("attacks list with floods", async ({ page }, info) => {
  await page.goto("/attacks")
  await expect(h1(page, "Attacks")).toBeVisible()
  await expect(page.getByRole("list", { name: "Sessions" })).toBeVisible()
  // The headline says how much of the day came in floods, and from how many addresses.
  await expect(page.getByText(/of them in floods from \d+ addresses/)).toBeVisible()
  const floodRows = page.getByRole("link", {
    name: /opened [\d,]+ (RDP|Telnet|SSH|HTTP) connections/,
  })
  await expect(floodRows.first()).toBeVisible()
  await settle(page)
  // The list is newest first: bring the first flood row into view for the shot.
  await floodRows.first().scrollIntoViewIfNeeded()
  await page.evaluate(() => window.scrollBy(0, -280))
  await shoot(page, "attacks-floods", info.project.name)

  // Only floods: the choice is in the URL, so the view can be shared.
  await page.getByRole("radio", { name: "Show only floods" }).click()
  await expect(page).toHaveURL(/[?&]kind=burst/)
  await expect(page.getByText(/came in floods from \d+ addresses/)).toBeVisible()
  await expect(page.getByText(/End of the list · [\d,]+ sessions in \d+ rows/)).toBeVisible()
  await settle(page)
  await shootTall(page, "attacks-floods-only", info.project.name)

  // Without floods: no group row is left.
  await page.getByRole("radio", { name: "Hide floods" }).click()
  await expect(page).toHaveURL(/[?&]kind=session/)
  await expect(page.getByText(/without the [\d,]+ connections that came in floods/)).toBeVisible()
  await expect(floodRows).toHaveCount(0)
  await settle(page)

  // Back to All: the parameter is gone.
  await page.getByRole("radio", { name: "Show everything, floods included" }).click()
  await expect(page).not.toHaveURL(/kind=/)
})

test("flood group page", async ({ page }, info) => {
  await page.goto("/attacks?kind=burst")
  await expect(page.getByRole("list", { name: "Sessions" })).toBeVisible()
  await page
    .getByRole("link", { name: /opened 812 RDP connections/ })
    .first()
    .click()
  await expect(page).toHaveURL(/\/attacks\/burst-[0-9a-f]{24}$/)
  await expect(groupTitle(page)).toBeVisible()
  await expect(page.getByText(/None of the 812 connections got in/)).toBeVisible()
  await expect(page.getByText("Credentials tried")).toBeVisible()
  await expect(page.getByRole("list", { name: "Events" })).toBeVisible()
  // The other group of the same address and hour is one click away.
  await expect(page.getByRole("list", { name: "Flood groups of the same hour" })).toBeVisible()
  // A group has no terminal to replay.
  await expect(page.getByText("Terminal replay")).toHaveCount(0)
  await settle(page)
  await shoot(page, "session-flood-group-top", info.project.name)
  await shootTall(page, "session-flood-group", info.project.name)

  // Credentials open the Trends filters.
  await page.getByRole("link", { name: /^Administrator: 812/ }).click()
  await expect(page).toHaveURL(/\/trends\?username=Administrator/)
})

test("an event link finds the group that folded its connection", async ({ page }, info) => {
  await page.goto("/attacks?kind=burst")
  await expect(page.getByRole("list", { name: "Sessions" })).toBeVisible()
  // A moment inside the group's hour, as an event of one of its connections would carry.
  const at = await page.evaluate(async () => {
    const res = await fetch("/api/v1/sessions?kind=burst&limit=50")
    const body = (await res.json()) as { items: { connections: number; started_at: string }[] }
    const group = body.items.find((s) => s.connections === 812)
    if (!group) throw new Error("no 812-connection group in the mock")
    return new Date(Date.parse(group.started_at) + 5 * 60_000).toISOString()
  })
  await page.goto(`/attacks/Zq3_n8WcX1p?at=${encodeURIComponent(at)}`)
  await expect(groupTitle(page)).toBeVisible()
  await expect(
    page.getByText("The connection you opened (Zq3_n8WcX1p) is one of them."),
  ).toBeVisible()
  await settle(page)
  await shoot(page, "session-flood-folded", info.project.name)

  // Without ?at= the same id is simply not found.
  await page.goto("/attacks/Zq3_n8WcX1p")
  await expect(page.getByText("Session not found")).toBeVisible()
})

test("attacker profile counts its floods", async ({ page }, info) => {
  await page.goto("/attackers/198.51.100.200")
  await expect(h1(page, "198.51.100.200")).toBeVisible()
  await expect(page.getByRole("link", { name: /of which [\d,]+ in floods/ })).toBeVisible()
  await settle(page)
  await shoot(page, "attacker-floods", info.project.name)
})
