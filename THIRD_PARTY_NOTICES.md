# Third-party notices

SuckerPot ships a few pieces of third-party material. Software dependencies keep their own licences (see each package's lockfile); this file covers data that is bundled in the repository.

## Common passwords list

`api/api/data/common-passwords.txt` lists 1000 very common passwords (12 characters or longer), used to refuse weak dashboard passwords. It is a filtered copy of the "100k most used passwords" list of the UK National Cyber Security Centre (NCSC).

- Contains public sector information licensed under the [Open Government Licence v3.0](https://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/).
- Obtained from the [SecLists](https://github.com/danielmiessler/SecLists) project (`Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt`), which is distributed under the MIT licence. Copyright (c) Daniel Miessler and contributors.
- Changes: only entries of at least 12 characters, ASCII only, lower-cased, duplicates removed, the first 1000 by frequency kept.

## MITRE ATT&CK

`ingest/rules/attack/techniques.yaml` lists a small subset of the technique ids, names and tactics of MITRE ATT&CK®, used to label what attackers did and to draw the Techniques page. The ids, names and tactics are taken from <https://attack.mitre.org/>.

- MITRE ATT&CK® is a registered trademark of The MITRE Corporation. SuckerPot is not affiliated with or endorsed by MITRE.
- © 2015-2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation, under the [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/).
- Changes: only the technique ids, names and tactics are kept, each with the SuckerPot "stage" it is told under. The mapping rules in `ingest/rules/attack/mapping.yaml` are SuckerPot's own.

## XARF schemas

`reporting/suckerpot_reporting/schemas/xarf-4.2.0/` holds the JSON schemas of XARF version 4.2.0 (the core schema, the master schema and the 33 type schemas), used to validate every X-ARF report before it is sent. They are copied unchanged from the [xarf-spec](https://github.com/xarf/xarf-spec) repository, tag `v4.2.0`.

- Distributed under the MIT licence. Copyright (c) 2025 XARF Project. The licence text is in `LICENSE` next to the schemas.
- Changes: one product name removed from the `examples` list of `bot_name` in `types/connection-infected-host.json` (an annotation only; no rule changes).
