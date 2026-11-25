import { expect, test } from "@playwright/test"
import { h1, settle, shoot, shootTall } from "./helpers"

test("malware samples tab", async ({ page }, info) => {
  await page.goto("/malware?view=samples")
  await expect(h1(page, "Files")).toBeVisible()
  await expect(page.getByRole("list", { name: "Samples" })).toBeVisible()
  await settle(page)
  await shootTall(page, "malware-samples", info.project.name)

  await page.goto("/malware?view=samples&kind=Script")
  await expect(page.getByRole("list", { name: "Samples" })).toBeVisible()
  await settle(page)
  await shoot(page, "malware-samples-filtered", info.project.name)
})

test("malware urls show fetch status", async ({ page }, info) => {
  await page.goto("/malware")
  await expect(page.getByText("Fetched").first()).toBeVisible()
  await settle(page)
  await shoot(page, "malware-fetch-status", info.project.name)
})

test("sample detail", async ({ page }, info) => {
  await page.goto("/malware?view=samples")
  const list = page.getByRole("list", { name: "Samples" })
  await list
    .getByRole("link", { name: /Mirai, ELF ARM 32-bit/ })
    .first()
    .click({ position: { x: 4, y: 4 } })
  await expect(h1(page, "Mirai")).toBeVisible()
  await expect(page.getByRole("list", { name: "Steps of the chain" })).toBeVisible()
  await expect(page.getByRole("list", { name: "Detection rules" })).toBeVisible()
  await settle(page)
  await shootTall(page, "sample-detail", info.project.name)

  // Download needs the administrator's password again.
  await page.getByRole("button", { name: "Download as archive" }).click()
  const dialog = page.getByRole("dialog")
  await expect(dialog.getByText("infected")).toBeVisible()
  await expect(dialog.getByLabel("Your password")).toBeVisible()
  await shoot(page, "sample-archive-dialog", info.project.name)
  await page.keyboard.press("Escape")

  // A script with a decoded layer.
  await page.goto("/malware?view=samples&kind=Script")
  await page
    .getByRole("list", { name: "Samples" })
    .getByRole("link")
    .first()
    .click({ position: { x: 4, y: 4 } })
  await expect(page.getByText("Deobfuscated script").first()).toBeVisible()
  await settle(page)
  await shootTall(page, "sample-detail-script", info.project.name)

  await page.goto(`/malware/samples/${"0".repeat(64)}`)
  await expect(page.getByText("This sample is not in the collection")).toBeVisible()
})

test("settings egress card", async ({ page }, info) => {
  await page.goto("/settings")
  await expect(page.getByText("Outbound traffic leaves through the VPN.")).toBeVisible()
  await expect(page.getByTestId("exit-ip")).toHaveText(/•/)
  await page.getByRole("button", { name: "Show" }).click()
  await expect(page.getByTestId("exit-ip")).toHaveText(/192\.0\.2\./)
  await page.getByRole("button", { name: "Hide" }).click()
  await settle(page)
  await shootTall(page, "settings-egress", info.project.name)
})
