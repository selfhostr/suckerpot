# Handle replies to reports

SuckerPot can read the answers to your abuse reports. It reads a mailbox that you set up for reports, sorts each reply by what it says, and links it to the report it answers. The report page then shows the outcome: an automatic receipt, a ticket number, a resolution, a rejection or a bounce.

Replies are optional. Without a mailbox you can still paste a reply, or upload an `.eml` file, on the report page. The outcome is then set the same way.

Related pages: [Takedowns](takedowns.md) (what happens to the reported targets), [Configuration](configuration.md#replies-to-reports-m26) (every variable), and the design in [docs/design/m26.md](design/m26.md).

## Before you start

You need:

- A mailbox for reports. Use a dedicated mailbox or an alias that only receives replies. Do not use your personal mailbox. The reply address you put in your reports should be this mailbox.
- An IMAP account with TLS (port 993, or port 143 with STARTTLS). Plain text is not offered.
- The VPN tunnel from [Anonymous egress](deployment.md#anonymous-egress-vpn), running.
- `ABUSE_REPLIES_ENABLED=true` in `.env`. The worker is off until you set it.

Proton mail needs Proton Bridge for IMAP. SuckerPot does not include Bridge. Proton users can still paste replies.

## Set up the mailbox

Open **Settings > Reporting > Replies**. Only an administrator sees this card.

| Field | What to enter |
| --- | --- |
| Read replies from this mailbox | Switch on when the settings are right. |
| Server | The DNS name of the IMAP server, not an IP address, for example `imap.example.net`. |
| Port | `993` for TLS (the default), or `143` for STARTTLS. |
| Security | TLS or STARTTLS. |
| Username | The login of the mailbox. |
| Password | Stored encrypted. It is never shown again. Leave it empty later to keep it. |
| Folder to read | `INBOX` by default. |
| Check every (minutes) | 5 to 1440, 15 by default. |
| After a reply is read | Only mark as read, or move to a folder. |
| Move to | The folder for processed replies. It must differ from the folder you read. Press **Test connection** to list the folders. |
| Mail provider name | The trusted provider name. See the next section. |
| Ignore mail before | Mail older than this date is never read. |

Saving asks for your dashboard password again. The first save needs the mailbox password. Changing the server, port, user name or security also needs the mailbox password again, even when a password is already stored.

Buttons:

- **Test connection** logs in, lists the folders and reports what it found. It does not read any mail.
- **Check now** reads the mailbox at once, without waiting for the interval.

The status line under the card shows when the mailbox was last checked, or the last error, in one sentence.

### The VPN rule

Replies are read through the VPN, like every other outbound request of SuckerPot. The mailbox server never sees your home address.

If the VPN is down, nothing is sent and nothing is read. The worker does not open a connection at all. The status shows the code `egress_closed`. When the tunnel is back, the next check reads the mail that arrived in the meantime.

### Shared mailboxes

SuckerPot warns you when the mailbox is on a free or shared mail domain. The card says: "This looks like a free or shared mailbox: use a mailbox dedicated to reports."

Why this matters:

- A reply from a free mail domain says nothing about the organisation you wrote to. Anyone can open a free account.
- For these domains, SuckerPot trusts one exact address only: the address of the recipient's mailbox, or an address you chose to trust. The domain alone never counts.
- A free-domain sender never makes a mail relevant, and never matches a report by its domain.

You can still use such a mailbox. The results are then more often "Reply not understood" or "Check it". A dedicated mailbox on your own domain gives better results.

## Find the trusted provider name

SuckerPot checks the **Authentication-Results** header that your mail provider adds to each mail it delivers. This check is what proves that a reply really came from the recipient's domain.

The header starts with a name, then a semicolon. That name is the **trusted provider name**. Enter it in the **Mail provider name** field. Only the first header with that name counts. Without the name, no reply is ever treated as authenticated. Then a reply is verified only when it matches your Message-ID from a trusted sender, or when you confirm it by hand.

To find it:

1. Send a test mail from another account to the report mailbox. Wait until it arrives.
2. Open the mail in your mail app and show the full headers (the "original message" or "show source" view).
3. Find the line that starts with `Authentication-Results:`.
4. Copy the first word after the colon, without the semicolon.

For example, this header:

```
Authentication-Results: mx.example.net; dkim=pass header.d=example.org; dmarc=pass header.from=example.org
```

gives the trusted provider name `mx.example.net`.

Notes:

- Use a mail that was delivered to the mailbox. A copy in your sent folder has no such header.
- SuckerPot compares the name in lower case. Letters, digits, dots and hyphens are allowed, up to 255 characters.
- If the header has no such line, your provider does not add one. Then leave the field empty.

## How replies are matched

Each reply is matched to one report by the first rule that fits. The rules run in this order.

| Order | Method | What it looks at |
| --- | --- | --- |
| 1 | `message_id` | The `In-Reply-To` or `References` header quotes the Message-ID of a report that SuckerPot sent through SMTP. |
| 2 | `token` | A 12-character reference, after `ref` (for example `ref 3f9a1c7b2e4d`), in the subject or the first 8 KiB of the body. |
| 3 | `dsn` | A delivery failure notice whose original mail has a Message-ID or a reference from rule 1 or 2. |
| 4 | `ticket` | A ticket number that an earlier reply from the same domain already linked to a report. |
| 5 | `sender_domain` | The sender's exact domain belongs to the recipient of exactly one report sent in the last 120 days. |
| — | `none` | No match. The mail is kept only if it is a delivery failure or comes from a party you wrote to. Otherwise it is not stored at all. |

### The reply reference

Each report has a random reference of 12 hexadecimal characters. It is not linked to any internal id.

The reference goes into the subject of the report, by default in the form `(ref 3f9a1c7b2e4d)`. You can also put it in the body. The setting is `reference_style`, a control named Reply reference in Settings, Reporting:

| Value | Effect |
| --- | --- |
| `subject` (default) | The reference is in the subject. |
| `subject_and_body` | Also one last body line: `Ref: 3f9a1c7b2e4d`. |
| `off` | No reference. Only the Message-ID of SMTP sends can match. |

The reference is random: it reveals nothing about you or the monitored system. It is public, though, because the format is in this project's code. If that bothers you, move the `{ref}` placeholder in the subject template or choose `off`.

### Message-ID

Our Message-ID counts as proof only when the reply comes from a party we wrote to. Anyone who saw the report can quote a Message-ID. A forwarded copy of your report is not a reply from the provider.

## Verified and unverified replies

A reply can change the outcome of a report only when it is **verified**. A reply is verified when one of these is true:

- It matches by Message-ID and comes from a trusted sender.
- It is a delivery failure that matches by Message-ID, and it is authenticated or comes from a trusted sender.
- Authentication passed (DKIM or DMARC, aligned with the sender's domain) and the sender is a trusted sender.
- You confirmed it by hand.

"Trusted sender" means the exact domain of the recipient's mailbox, the override mailbox, or a reply domain you added. Subdomains are other parties. For example, `tickets.example.org` is not `example.org` unless you add it as a reply domain.

An unverified reply is still stored and shown. It does not change the outcome. The report shows **Check it** on that reply, and the outcome card asks you to look at it.

This matters for a case like this: someone who received a forwarded report writes "resolved" to the reply address. That mail has a reference, but no proof that it came from the provider. It stays unverified until you check it.

### Confirm a reply

On **Reports > Replies to check** (the banner on the Reports tab shows the count), you can:

- **Link to report** when the match is wrong or missing.
- **Confirm** to mark the reply as verified.
- **Trust this domain** to add the sender's domain to the recipient's reply domains. Future replies from that domain are then trusted.

## What the classification means

Each reply gets one class. The class is set by the first rule that fits. The rules are YAML files in `ingest/rules/replies/`, and you can read them there.

| Class | Label in the dashboard | Meaning |
| --- | --- | --- |
| `resolved` | Resolved | The provider says it acted: suspended, removed, terminated or null-routed. |
| `rejected` | Rejected | The provider says it is not theirs, not hosted by them, or asks you to use a web form. |
| `ticket_opened` | Ticket opened | A ticket or case number was found, and the mail is an automatic acknowledgement or says a ticket was created. |
| `auto_ack` | Automatic receipt | An automatic reply, an out-of-office message or a bulk receipt, without a ticket. |
| `bounce` | Bounced | A delivery failure. Your report did not reach the desk. |
| `human_reply` | Answered by a person | Not automatic, from a known domain, with at least 20 characters of text. |
| `unknown` | Reply not understood | None of the rules fit. Read the mail yourself. |

The **outcome** of a report comes from the verified replies. When several replies came back, the strongest one wins, in this order:

1. Resolved
2. Rejected
3. Ticket opened
4. Answered by a person
5. Automatic receipt
6. Bounced
7. Reply not understood

A report with no reply has the outcome **No answer yet**. After 14 days (`ABUSE_NO_ANSWER_DAYS`) it reads **No answer**.

A bounce also marks the report for review, and the report page suggests another mailbox for the recipient.

SuckerPot never closes a report by itself. A "resolved" outcome does not close it. You decide when to close.

### Set the outcome by hand

If the automatic result is wrong, or the provider answered by phone, set the outcome yourself. On the report page, open the **Outcome** card, choose **Set outcome**, pick the outcome, the date and an optional note. The manual outcome wins over the automatic one. **Back to automatic** removes it.

## What SuckerPot reads and stores

Incoming mail is treated as hostile. The rules below apply to every mail.

- **Relevance first.** SuckerPot reads the headers first. A mail is fetched in full only when its headers show a reference or Message-ID of one of your reports, a ticket number, a delivery failure, or a sender from a party you wrote to. Other mail is counted as "ignored". Nothing is stored and its flags are not changed.
- **Size.** A header block over 64 KiB is skipped. A mail over 256 KiB is cut at 256 KiB and marked as truncated (`ABUSE_REPLY_MAX_BYTES`).
- **Bounded parsing.** At most 50 parts, nested at most 5 levels deep. Each text part is capped at 128 KiB.
- **Attachments** are never opened or decoded. SuckerPot stores only how many there were, their types and their size.
- **HTML** is never rendered. If a mail has no text part, the text is taken from the HTML and all tags are removed. No link is kept or made clickable.
- **Excerpt.** At most 2,000 characters of the reply are kept, without quoted text. Excerpts are deleted after 180 days (`ABUSE_REPLY_EXCERPT_DAYS`). Unmatched replies are deleted after 180 days.
- **Addresses.** Only the sender's domain is shown to viewers. Administrators also see the sender's address.
- **Pasted mail.** The raw text of a pasted or uploaded reply is cleared right after it is read.

Limits per poll: 50 mails (`ABUSE_REPLY_MAX_PER_POLL`) and 500 per UTC day (`ABUSE_REPLY_DAILY_CAP`). Each poll stops after 120 seconds (`ABUSE_REPLY_POLL_DEADLINE_S`). Mail that does not fit waits for the next poll.

### Paste a reply

On a report page, choose **Add a reply**. Paste the text of the mail, or upload an `.eml` file. The reply is read at once, through the same rules. It needs no mailbox. You can paste 20 replies per hour.

## The worker never deletes mail

The mailbox is only read and marked. SuckerPot does not:

- delete, expunge or flag mail as deleted;
- write, rename or create folders, or change access rights;
- send or answer mail.

It changes only two things, and only after the reply is saved in the database:

| Setting | Effect |
| --- | --- |
| **Mark as read** (default) | Sets the `\Seen` flag on the mail. |
| **Move** | Moves the mail to the folder you chose (IMAP `MOVE`). If the server has no `MOVE`, the mail is marked as read instead, and the status says so. |

Fetching never marks mail as read: SuckerPot uses `BODY.PEEK`. SuckerPot also does not rely on unread mail. It reads everything since the last position, so mail you read yourself is still picked up.

If you want an empty mailbox, do that yourself in your mail app.

## Errors

The status line shows one of these codes in plain words. Server answers and mail content are never stored or logged.

| Code | What it means | What to do |
| --- | --- | --- |
| `not_configured` | No mailbox is saved. | Save the mailbox in Settings. |
| `paused` | The mailbox is saved but switched off. | Switch **Read replies from this mailbox** on. |
| `egress_closed` | The VPN tunnel is down, so nothing was attempted. | Check the VPN tab in Settings. Replies are read again once it is back. |
| `tls_failed` | The connection could not be secured. The server does not offer STARTTLS, or the certificate did not check out. | Check the server name, the port and the security setting. |
| `auth_failed` | The server refused the login. | Check the user name and password. Some providers need an app password. |
| `no_folder` | The folder to read does not exist. | Correct the folder name. |
| `no_move_folder` | The folder to move replies to is missing, or the server refused the move. | Create the folder, or correct its name. |
| `timeout` | The server did not answer in time. | Try again later. |
| `network` | The connection to the server failed. | Check the server name and the tunnel. |
| `protocol` | The server answered in a way SuckerPot does not understand. | Check that the port is an IMAP port, not a POP3 or SMTP one. |
| `internal` | A problem inside SuckerPot, such as the database. | Check the ingest logs. No mail content is in them. |

A single bad mail does not stop the mailbox. SuckerPot counts it as `failed` and moves on to the next one. A broken connection or database stops the poll, and the poll starts again from the same place next time.

Counters on the card: `fetched`, `relevant`, `matched`, `ignored`, `oversize` and `failed`.

## Related

- [Takedowns](takedowns.md): what happens to the reported targets after you send.
- [Configuration](configuration.md#replies-to-reports-m26): every variable and its range.
- [Dashboard](ui.md#results-m26-m27): the Results page, where the outcomes are counted.
- [Design M26](design/m26.md): the full design, with the invariants and the tests.
