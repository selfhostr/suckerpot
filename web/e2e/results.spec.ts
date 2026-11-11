import { expect, test } from "@playwright/test"
import { h1, settle, shoot } from "./helpers"

// M26/M27: results of abuse reports and replies. Mock data only.

test("results page", async ({ page }, info) => {
  await page.goto("/defend/results")
  await expect(h1(page, "Results")).toBeVisible()
  await expect(page.getByText("Did anyone answer?")).toBeVisible()
  await expect(
    page
      .getByRole("table", { name: "Tracked targets" })
      .or(page.getByRole("list", { name: "Tracked targets" })),
  ).toBeVisible()
  await settle(page)
  await shoot(page, "results", info.project.name, true)
})

test("results target", async ({ page }, info) => {
  await page.goto("/defend/results/targets/4")
  await expect(page.getByText("Timeline", { exact: true })).toBeVisible()
  await settle(page)
  await shoot(page, "results-target", info.project.name, true)
})

test("outcome card and replies on a sent report", async ({ page }, info) => {
  await page.goto("/defend/abuse/3c4d5e6f-7a8b-4c9d-8e0f-6f7a8b9c0d06")
  await expect(page.getByText("Outcome", { exact: true })).toBeVisible()
  await expect(page.getByRole("list", { name: "Replies" })).toBeVisible()
  await settle(page)
  await shoot(page, "abuse-outcome", info.project.name, true)
})

test("settings replies card", async ({ page }, info) => {
  await page.goto("/settings?tab=reporting")
  await expect(page.getByText("Read replies from this mailbox")).toBeVisible()
  await settle(page)
  await shoot(page, "settings-replies", info.project.name, true)
})

test("settings mailbox: free or shared mailbox and a failed check", async ({ page }, info) => {
  await page.goto("/settings?tab=reporting&imap=shared")
  await expect(page.getByText("This looks like a free or shared mailbox")).toBeVisible()
  await expect(page.getByText("The secure connection to the mail server failed.")).toBeVisible()
  await expect(page.getByLabel("Mail provider name")).toHaveValue("")
  await settle(page)
  await shoot(page, "settings-imap-shared", info.project.name, true)
})

test("settings mailbox: trusted provider name and password required", async ({ page }, info) => {
  await page.goto("/settings?tab=reporting&imap=password")
  await expect(page.getByLabel("Mail provider name")).toHaveValue("mx.example.net")
  await page.getByRole("button", { name: "Save mailbox settings" }).click()
  const dialog = page.getByRole("dialog")
  await dialog.getByLabel(/password/i).fill("demo-password")
  await dialog.getByRole("button", { name: "Save", exact: true }).click()
  await expect(page.getByText("Enter the mailbox password again.")).toBeVisible()
  await settle(page)
  await shoot(page, "settings-imap-password", info.project.name)
})

test("reply without a sender address cannot be trusted", async ({ page }, info) => {
  await page.goto("/defend/abuse?status=replies")
  await page.getByRole("button", { name: "Trust this sender" }).first().click()
  await expect(page.getByText(/has no sender address/)).toBeVisible()
  await settle(page)
  await shoot(page, "replies-no-address", info.project.name, true)
})
