"""Advisory lock keys shared by services.

``ABUSE_SMTP_PROFILE``: ingest holds it in SHARED mode for the whole of a report mail (it reads
the SMTP profile and delivers), the API takes it EXCLUSIVELY to change or delete the profile, so a
profile write waits for a send in flight and a send never uses a half-changed profile.

``ABUSE_IMAP_PROFILE`` (M26): the same pattern for the replies mailbox. Ingest holds it SHARED
during a poll, the API takes it EXCLUSIVELY (with a lock timeout) to change or delete the profile.

``SAMPLE_TYPING`` (collector): the collector holds it EXCLUSIVELY while it turns new indicators
into fetch targets (an attacker typing a URL that already served a file), the analyzer holds it
SHARED while it decides whether a file is plain web content, so a decision never reads a typing
that is half written.
"""

ABUSE_SMTP_PROFILE = 25_001
ABUSE_IMAP_PROFILE = 26_001
SAMPLE_TYPING = 27_001
