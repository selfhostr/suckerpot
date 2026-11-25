import { expect, test } from "@playwright/test"
import { h1, settle, shoot } from "./helpers"

// The Attacks lists: every filter is in the URL, shows as a removable chip and clears in one click.

test("sessions: filters, chips, empty state and history", async ({ page }, info) => {
  await page.goto("/attacks")
  await expect(h1(page, "Attacks")).toBeVisible()
  await expect(page.getByRole("list", { name: "Sessions" })).toBeVisible()

  // Outcome: one of the six steps a session can reach.
  await page.getByRole("button", { name: /^Outcome/ }).click()
  await page.getByRole("option", { name: "Ran commands" }).click()
  await expect(page).toHaveURL(/[?&]stage=commands/)
  await expect(page.getByRole("button", { name: "Remove Outcome filter" })).toBeVisible()
  await expect(page.getByRole("list", { name: "Sessions" })).toBeVisible()

  // Back undoes it, Forward redoes it.
  await page.goBack()
  await expect(page).not.toHaveURL(/stage=/)
  await page.goForward()
  await expect(page).toHaveURL(/stage=commands/)

  // A country picked from the list and a tag typed in.
  await page.getByRole("button", { name: /^Country/ }).click()
  await page.getByRole("combobox", { name: "Search Country" }).fill("Netherlands")
  await page.getByRole("option", { name: "Netherlands", exact: true }).click()
  await expect(page).toHaveURL(/country=NL/)
  await settle(page)
  await shoot(page, "attack-filters-sessions", info.project.name)

  // Search an exact address nobody used: the empty state names the way out.
  await page.getByRole("textbox", { name: /Search ip address/i }).fill("192.0.2.250")
  await page.keyboard.press("Enter")
  await expect(page).toHaveURL(/src_ip=192\.0\.2\.250/)
  await expect(page.getByText("No sessions match these filters")).toBeVisible()
  await page.getByRole("button", { name: "Clear all" }).first().click()
  await expect(page).not.toHaveURL(/country=|stage=|src_ip=/)
  await expect(page.getByRole("list", { name: "Sessions" })).toBeVisible()
})

test("attackers: search, sort and chips", async ({ page }, info) => {
  await page.goto("/attackers?sort=sessions&order=asc&country=NL")
  await expect(h1(page, "Attackers")).toBeVisible()
  await expect(page.getByRole("list", { name: "Attackers" })).toBeVisible()
  await expect(page.getByRole("button", { name: "Remove Country filter" })).toBeVisible()
  await expect(page.getByRole("button", { name: /Switch to highest first/ })).toBeVisible()

  await page.getByRole("textbox", { name: "IP prefix" }).fill("198.51")
  await expect(page).toHaveURL(/q=198\.51/)
  await expect(page.getByRole("button", { name: "Remove IP prefix filter" })).toBeVisible()
  await settle(page)
  await shoot(page, "attack-filters-attackers", info.project.name)

  await page.getByRole("button", { name: "Remove Country filter" }).click()
  await expect(page).not.toHaveURL(/country=/)
  await page.getByRole("button", { name: "Clear all" }).click()
  await expect(page).not.toHaveURL(/q=/)
  // The sort is a view, not a filter: it stays.
  await expect(page).toHaveURL(/sort=sessions/)
})

test("networks: search by name or AS number, period", async ({ page }, info) => {
  await page.goto("/networks")
  const list = page.getByRole("list", { name: "Attacker networks" })
  await expect(list).toBeVisible()
  const all = await list.getByRole("listitem").count()
  expect(all).toBeGreaterThan(1)

  await page.getByRole("textbox", { name: "Network" }).fill("AS6449")
  await expect(page).toHaveURL(/q=AS6449/)
  await expect.poll(() => list.getByRole("listitem").count()).toBeLessThan(all)

  await page.getByRole("textbox", { name: "Network" }).fill("zzzz-no-such-network")
  await expect(page.getByText("No networks match these filters")).toBeVisible()
  await page.getByRole("button", { name: "Clear all" }).first().click()
  await expect(list.getByRole("listitem")).toHaveCount(all)
  await settle(page)
  await shoot(page, "attack-filters-networks", info.project.name)
})
