import { expect, test } from "@playwright/test"
import { h1, settle, shoot, shootTall } from "./helpers"

test("scripts library", async ({ page }, info) => {
  await page.goto("/scripts")
  await expect(h1(page, "Scripts")).toBeVisible()
  await expect(page.getByRole("list", { name: "Scripts" })).toBeVisible()
  await settle(page)
  await shootTall(page, "scripts", info.project.name)

  await page.goto("/scripts?view=new")
  await expect(page.getByRole("list", { name: "Scripts" })).toBeVisible()
  await settle(page)
  await shoot(page, "scripts-new", info.project.name)

  await page.goto("/scripts?technique=T1105&sensor=ssh")
  await expect(page.getByRole("list", { name: "Scripts" })).toBeVisible()
  await settle(page)
  await shoot(page, "scripts-filtered", info.project.name)
})

test("script detail", async ({ page }, info) => {
  await page.goto("/scripts/1")
  await expect(h1(page, "Script 1")).toBeVisible()
  await expect(page.getByRole("list", { name: "Commands with explanations" })).toBeVisible()
  await settle(page)
  await shootTall(page, "script-detail", info.project.name)

  // A long command line (an SSH key) wraps inside its code band.
  await page.goto("/scripts/4")
  await expect(h1(page, "Script 4")).toBeVisible()
  await settle(page)
  await shoot(page, "script-detail-long", info.project.name, true)

  await page.goto("/scripts/9999")
  await expect(page.getByText("This script is not in the library")).toBeVisible()
})
