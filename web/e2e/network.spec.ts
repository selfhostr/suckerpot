import { expect, test } from "@playwright/test"
import { h1, settle, shoot } from "./helpers"

// M29: the SuckerPot network. Mock data only (src/mocks/network.ts): documentation addresses and
// invented pseudonyms. `?network=member` starts as a member; the default is not a member.

test("network, not a member", async ({ page }, info) => {
  await page.goto("/network")
  await expect(h1(page, "SuckerPot network")).toBeVisible()
  await expect(page.getByText("You are not part of the SuckerPot network.")).toBeVisible()
  await expect(page.getByText("What is never shared")).toBeVisible()
  await settle(page)
  await shoot(page, "network-off", info.project.name, true)
})

test("network join dialog", async ({ page }, info) => {
  await page.goto("/network")
  await page.getByRole("button", { name: "Join the network" }).click()
  const dialog = page.getByRole("dialog")
  await expect(dialog.getByText("Join the SuckerPot network")).toBeVisible()
  await expect(dialog.getByRole("checkbox")).toHaveCount(0)
  await expect(dialog.getByText("What you share")).toBeVisible()
  await settle(page)
  await shoot(page, "network-join", info.project.name)
})

test("network, member overview", async ({ page }, info) => {
  await page.goto("/network?network=member")
  await expect(h1(page, "SuckerPot network")).toBeVisible()
  await expect(
    page.getByText(/The network took down 141 malware hosts and attack sources/),
  ).toBeVisible()
  await expect(page.getByRole("list", { name: "Network targets" })).toBeVisible()
  await settle(page)
  await shoot(page, "network-member", info.project.name, true)
})

test("network members", async ({ page }, info) => {
  await page.goto("/network/members?network=member")
  await expect(h1(page, "Members")).toBeVisible()
  await expect(page.getByText(/37 members in 9 countries/)).toBeVisible()
  await settle(page)
  await shoot(page, "network-members", info.project.name, true)
})

test("settings network, member, leave dialog", async ({ page }, info) => {
  await page.goto("/settings?tab=network&network=member")
  await expect(page.getByRole("button", { name: "Leave the network" })).toBeVisible()
  await settle(page)
  await shoot(page, "settings-network", info.project.name, true)
  await page.getByRole("button", { name: "Leave the network" }).click()
  await expect(page.getByRole("dialog").getByText("Leave the SuckerPot network?")).toBeVisible()
  await settle(page)
  await shoot(page, "settings-network-leave", info.project.name)
})

test("network sent drawer", async ({ page }, info) => {
  await page.goto("/settings?tab=network&network=member")
  await page.getByRole("button", { name: "See exactly what was sent" }).click()
  await expect(page.getByRole("dialog").getByText("What was sent")).toBeVisible()
  await expect(page.getByLabel(/^Data sent for/)).toBeVisible()
  await settle(page)
  await shoot(page, "network-sent", info.project.name)
})
