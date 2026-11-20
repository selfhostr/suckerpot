/**
 * MSW handler for the M24 setup checklist (docs/dev/design/m24.md section 3). Demo data only.
 * The VPN line follows the mocked gate, so trusting an exit on the VPN tab turns it green.
 * `?setup=done` shows a finished set-up.
 */
import { delay, http, HttpResponse, type RequestHandler } from "msw"
import type { SetupItem } from "@/lib/setup"
import { vpnGateOpen } from "./vpn"

function items(done: boolean): SetupItem[] {
  const gate = vpnGateOpen()
  return [
    done
      ? {
          id: "sensors",
          state: "ok",
          detail: "All 12 sensors sent an event in the last 24 hours.",
          href: "/settings",
        }
      : {
          id: "sensors",
          state: "warning",
          detail: "1 sensor has been silent for 24 hours: SIP.",
          href: "/settings",
        },
    gate
      ? {
          id: "vpn",
          state: "ok",
          detail: "The gate is open: outbound lookups leave through the VPN.",
          href: "/settings?tab=vpn",
        }
      : {
          id: "vpn",
          state: "warning",
          detail: "The gate is closed: outbound lookups are paused until the exit is trusted.",
          href: "/settings?tab=vpn",
        },
    done
      ? {
          id: "collector",
          state: "ok",
          detail: "Payload fetching is on and its gate is open.",
          href: "/malware",
        }
      : {
          id: "collector",
          state: "off",
          detail: "Payload fetching is off, so download URLs are recorded but not fetched.",
          href: "/malware",
        },
    done
      ? {
          id: "reporting_settings",
          state: "ok",
          detail: "The reply contact is set. The report texts are optional.",
          href: "/settings?tab=reporting",
        }
      : {
          id: "reporting_settings",
          state: "todo",
          detail: "Set the reply contact for abuse reports. The report texts are optional.",
          href: "/settings?tab=reporting",
        },
    done
      ? {
          id: "self_address",
          state: "ok",
          detail: "Your own address is set, so reports never contain it.",
          href: "/settings?tab=reporting",
        }
      : {
          id: "self_address",
          state: "todo",
          detail: "Add the public address of this system so reports can be checked against it.",
          href: "/settings?tab=reporting",
        },
    done
      ? {
          id: "abuse_worker",
          state: "ok",
          detail: "Abuse report drafts are being built.",
          href: "/defend/abuse",
        }
      : {
          id: "abuse_worker",
          state: "off",
          detail: "Abuse report drafts are off. Set ABUSE_REPORTS_ENABLED to turn them on.",
          href: "/defend/abuse",
        },
    done
      ? {
          id: "alerts",
          state: "ok",
          detail: "1 alert channel is set up.",
          href: "/settings?tab=alerts",
        }
      : {
          id: "alerts",
          state: "off",
          detail: "No alert channel yet. Add Discord, Teams or email to be told about attacks.",
          href: "/settings?tab=alerts",
        },
    done
      ? {
          id: "provider_keys",
          state: "ok",
          detail: "AbuseIPDB and GreyNoise keys are set.",
          href: "/settings?tab=keys",
        }
      : {
          id: "provider_keys",
          state: "off",
          detail: "No reputation keys. AbuseIPDB and GreyNoise add a score and a scanner label.",
          href: "/settings?tab=keys",
        },
    done
      ? {
          id: "network_feed",
          state: "ok",
          detail: "The community lists are up to date.",
          href: "/defend/blocklists?tab=network",
        }
      : {
          id: "network_feed",
          state: "off",
          detail: "The community lists are not fetched here.",
          href: "/defend/blocklists?tab=network",
        },
  ]
}

export const setupHandlers: RequestHandler[] = [
  http.get("/api/v1/setup/status", async () => {
    await delay(160)
    const done =
      typeof window !== "undefined" &&
      new URLSearchParams(window.location.search).get("setup") === "done"
    return HttpResponse.json({ items: items(done) })
  }),
]
