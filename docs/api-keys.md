# Add provider API keys

SuckerPot works without any API key. Every key below is optional. Each one adds one more source of context to the dashboard. Without it, that source is simply empty, and nothing else breaks.

```{admonition} Security note
:class: warning

The honeypot host is attacked on purpose. Treat every key stored on it as possibly exposed. Use keys with the fewest rights the provider offers, never reuse a key from another project, and rotate the keys from time to time. Never put a key that can write or push (a GitHub push token, for example) on this host.
```

## Where to enter a key

There are two ways. A key set in Settings overrides the same key in `.env`.

1. **Settings > API keys.** Choose **Set key** for a provider, paste the key and confirm with the admin password. The key is stored encrypted, is write-only (only its last four characters are shown back), and **Test key** makes one real call to check it. This needs `SETTINGS_ENCRYPTION_KEY` in `.env` (see [Enrichment keys in Settings](configuration.md#enrichment-keys-in-settings)).
2. **`.env`.** Put the key in the variable listed for the provider, then run `docker compose up -d`.

The Settings page lists seven providers: AbuseIPDB, GreyNoise Community, MaxMind GeoLite2, NVD, GitHub advisories, abuse.ch and VirusTotal. A key must be 16 to 128 printable characters with no spaces. Daily quotas are enforced by SuckerPot, so a key cannot be used up by mistake.

| Provider | Adds | `.env` variable | Cost |
| --- | --- | --- | --- |
| AbuseIPDB | Abuse score of attacker IPs | `ABUSEIPDB_API_KEY` | Free tier, 1,000 checks per day |
| GreyNoise Community | "Known scanner" labels | `GREYNOISE_API_KEY` | Free tier, about 50 checks per day |
| MaxMind GeoLite2 | Country, city and ASN | `MAXMIND_ACCOUNT_ID`, `MAXMIND_LICENSE_KEY` | Free account |
| NVD | Faster CVE watch | `NVD_API_KEY` | Free |
| GitHub advisories | Faster CVE watch | `GITHUB_ADVISORY_TOKEN` | Free |
| abuse.ch | URLhaus and ThreatFox answers | `ABUSECH_AUTH_KEY` | Free |
| VirusTotal | Verdicts for file hashes | `VIRUSTOTAL_API_KEY` | Free tier, low quota |

## AbuseIPDB

Adds the abuse score and report count of an attacker's IP address, shown on attacker profiles and used in blocklist scores.

1. Create a free account at <https://www.abuseipdb.com/register>.
2. Open your account, then the **API** tab.
3. Choose **Create Key**, give it a name such as `suckerpot`, and copy it.
4. Set it in Settings, or as `ABUSEIPDB_API_KEY`.

The free tier allows 1,000 checks per day. `ABUSEIPDB_DAILY_QUOTA` (default 1000) caps what SuckerPot uses. Results are cached for 24 hours. SuckerPot only reads from AbuseIPDB. It never reports addresses to it.

## GreyNoise Community

Adds a label that says whether an address is a known internet scanner, and whether it is harmless.

1. Create a free account at <https://viz.greynoise.io/signup>.
2. Sign in and open your account page. The API key is shown there.
3. Copy it and set it in Settings, or as `GREYNOISE_API_KEY`.

The Community API allows about 50 lookups per day (`GREYNOISE_DAILY_QUOTA`, default 50).

## MaxMind GeoLite2

Adds country, city and network (ASN) for each address. Without a key, SuckerPot uses DB-IP Lite instead, which needs no key.

1. Create a free account at <https://www.maxmind.com/en/geolite2/signup> and confirm your e-mail address.
2. Sign in. The **Account ID** is the number at the top of the account page.
3. Open **Manage license keys** and choose **Generate new license key**.
4. Copy the key at once. It is shown only once.
5. Enter both in Settings (the form asks for the Account ID and the key), or set `MAXMIND_ACCOUNT_ID` and `MAXMIND_LICENSE_KEY`.

Notes:

- A brand-new key can take a few minutes before downloads stop returning `401`. Wait, then use **Test key** again.
- Ingest downloads the databases itself and refreshes them every `GEOIP_REFRESH_DAYS` days (default 30).
- The `.mmdb` files are never committed to the repository, because the licence does not allow redistribution.
- The GeoLite2 licence requires credit: "This product includes GeoLite2 data created by MaxMind, available from https://www.maxmind.com". The dashboard shows it for you. See [Data sources and attribution](configuration.md#data-sources-and-attribution).

## NVD

Raises the rate limit of the CVE watch from 5 to 50 requests per 30 seconds.

1. Open <https://nvd.nist.gov/developers/request-an-api-key>.
2. Enter your organization name and e-mail address, and accept the terms.
3. Open the activation e-mail and follow its link. The key is shown on that page.
4. Set it in Settings, or as `NVD_API_KEY`.

SuckerPot spends at most `CVE_NVD_DAILY_QUOTA` requests per day (default 200).

## GitHub advisories

Raises the limit of the GitHub advisories feed from 60 requests per hour (without a token).

1. On GitHub, open **Settings > Developer settings > Personal access tokens > Fine-grained tokens**.
2. Choose **Generate new token** and give it a short expiry.
3. Under **Repository access**, choose **Public repositories (read-only)**.
4. Leave **every permission empty**. Public advisories need none.
5. Generate the token, copy it, and set it in Settings or as `GITHUB_ADVISORY_TOKEN`.

Never use a token that can push or that belongs to your main workflow. If this host is compromised, the token must be worth nothing.

## abuse.ch (URLhaus and ThreatFox)

Adds answers about download URLs and indicators from URLhaus and ThreatFox, shown on the Infrastructure page.

1. Sign in at <https://auth.abuse.ch/> (a free account).
2. Create or copy your **Auth-Key**.
3. Set it in Settings, or as `ABUSECH_AUTH_KEY`.

Only the indicator value is sent, to the fixed abuse.ch hosts. The two services share `ABUSECH_DAILY_QUOTA` (default 1000).

## VirusTotal

Adds verdicts and links for file hashes. Only hashes are sent, never files.

1. Create a free account at <https://www.virustotal.com/gui/join-us>.
2. Open your profile menu, then **API key**, and copy it.
3. Set it in Settings, or as `VIRUSTOTAL_API_KEY`.

The free tier is small (about 500 requests per day and 4 per minute). SuckerPot spaces requests 16 seconds apart and stops at `VIRUSTOTAL_DAILY_QUOTA` (default 400).

## Rotating a key

1. Create the new key at the provider.
2. Replace it in Settings (or in `.env`, then `docker compose up -d`).
3. Revoke the old key at the provider.
