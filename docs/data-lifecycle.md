# Local backup, restore, and migration

BountyBreak keeps this workflow outside MCP. A human runs the administrative CLI, reviews its JSON result, and explicitly chooses when to point the dashboard or an MCP client at a restored directory. An agent cannot invoke a restore through BountyBreak tools.

## Check the store

```powershell
python data_lifecycle.py doctor --data-dir C:\private\bountybreak-data
```

`doctor` is read-only. It reports current, legacy, corrupt, and unsupported future-schema engagement records. Corrupt records stay on disk. They are not repaired, rewritten, or silently excluded from a backup.

## Create and verify a backup

```powershell
python data_lifecycle.py backup --data-dir C:\private\bountybreak-data
python data_lifecycle.py verify --archive C:\private\bountybreak-data\.backups\bountybreak-backup-TIMESTAMP.zip
```

The default archive is written below `.backups`. It includes every regular, non-link file under each valid engagement directory and the optional root `tool-registry.json`. It omits previous backups, root environment files, caches, logs, and the rebuildable public intelligence database.

The archive manifest records every relative path, byte count, and SHA-256 value. Verification rejects path traversal, symbolic links, reparse points, encrypted entries, duplicates, undeclared files, unsupported schemas, manifest mismatches, and excessive expansion. The backup command verifies its completed archive before reporting success.

Backups are local ZIP files and are not encrypted. Keep them on an encrypted volume or in a trusted encrypted backup service. BountyBreak assumes its source records and evidence are already sanitized; the backup command does not attempt to discover secrets hidden in free-form evidence.

## Restore without overwriting

```powershell
python data_lifecycle.py restore `
  --archive C:\path\to\bountybreak-backup.zip `
  --destination C:\private\bountybreak-restored
python data_lifecycle.py doctor --data-dir C:\private\bountybreak-restored
```

The destination must not exist. BountyBreak verifies the complete archive, extracts into a temporary sibling directory, validates the restored store, and only then renames it to the requested destination. It never merges into or replaces a live data directory.

After review, start BountyBreak or register MCP with the new path. Keep the old directory unchanged until the restored copy has been opened and checked.

## Migrate with rollback

```powershell
python data_lifecycle.py migrate --data-dir C:\private\bountybreak-data
```

Migration stops if any record is corrupt, unsafe, or from a newer schema. If migration is needed, it creates and verifies a full `pre-migration` archive before changing a record. Each engagement write is atomic. The JSON result identifies the rollback archive and its SHA-256.

BountyBreak does not perform a lossy reverse transform. To downgrade or roll back, restore the pre-migration archive into a new directory and point the older compatible build at that restored path.

## Recovery rules

- Preserve the original data directory and failed record until recovery is complete.
- Use `doctor` to identify the exact record and failure class.
- Restore a verified archive into a new directory; never hand-edit the only copy.
- A future schema requires a newer compatible BountyBreak build. It is not converted by guessing.
- A malformed record requires an independent clean copy or deliberate manual repair after another filesystem-level backup.
