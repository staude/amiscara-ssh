# amiscara-ssh - Projektregeln

## Zweck

Gemeinsamer SSH-Client (Rust, russh) für Amiscara Connect und Amiscara Agents. Entscheidung und Grenze des Crates: `docs/konzept.md` in `staude/amiscara-connect`, Abschnitt „Gemeinsames SSH-Crate“. Das Repo ist öffentlich.

Persönliche, nicht eingecheckte Ergänzungen gehören in `CLAUDE.local.md` (steht in `.gitignore`).

## Öffentlichkeit

Fremde Produkte werden nirgends als Vorbild oder Quelle genannt: nicht in Dateien, Issues, Kommentaren, PRs oder Commit-Messages.

## Arbeitsweise

- Edition 2024, Lints im `[workspace.lints]` (`unsafe_code = "forbid"`, `unwrap_used`, `dbg_macro`, `todo` verboten).
- Nur SSH ins Crate. Was zu einer App gehört (herdr-Socket, Gates, Sitzungslisten), bleibt in der App.
- Passwörter und Passphrasen nie in Fehlertexten, `Debug` oder Logs; im Speicher als `Zeroizing`.
- Tests nie gegen fremde oder produktive Server, nur gegen den lokalen Container.
- Branch `feature/<n>-slug` oder `fix/<n>-slug`, PR, Squash-Merge, Branch beim Mergen löschen.
- `CHANGELOG.md` nach Keep a Changelog, Eintrag pro Merge. Release wie im README.
- Commit-Messages auf Englisch, Conventional Commits.
