# Offline Thesis Backup Assistant (PySide6 + Watchdog)

A small, reliable, offline backup assistant for research and thesis work. It monitors a local source folder and mirrors changes to:
- your OneDrive local sync folder, and
- a selected local drive/folder,
while preserving the original directory structure under a dedicated subfolder (default: `backup`).

No cloud APIs, no databases, minimal footprint. Designed for frequent small edits to documents and code.

## Highlights
- Real-time “save-to-backup” toggle: backup immediately on file save or creation
- Optional periodic scan: catch missed changes at a configurable interval
- Two targets: OneDrive local sync folder + a local drive/folder
- Preserve structure: files are mirrored under `<target>/<backup_subfolder>/<relative_path>`
- File type filters: simple checkboxes preloaded with common doc/code types
- Smart exclusions:
  - Skips environment/library folders: `node_modules`, `vendor`, `__pycache__`, `site-packages`, etc.
  - Skips cache/extensions: `.pyc`, etc.
  - Skips Office temp lock files like `~$*.docx` / `~$*.xlsx`
- Conflict-safe: if the destination exists with different content, a second copy is saved as `*.conflict-YYYYMMDD-HHMMSS`
- Initial backup mode:
  - If the `backup` subfolder already exists in both targets, perform incremental sync
  - Otherwise, enqueue a one-time initial backup of eligible files
- Lightweight logging only:
  - JSON line logs per day in `backup/logs/backup-YYYY-MM-DD.jsonl`
  - Auto-retain last 7 days; fallback file on write failure

## Requirements
- Windows (tested)
- Python 3.9+
- Packages: `PySide6`, `watchdog`

Install:
```bash
pip install PySide6 watchdog
```

## Run
```bash
python backup/backup.py
```

## Quick Start
1. Open the app.
2. Set:
   - Source folder (your thesis/code workspace)
   - OneDrive local sync folder (e.g., `C:\Users\<you>\OneDrive` or `OneDrive - <Org>`)
   - Local backup folder or select a drive via “Select Local Drive”
   - Target subfolder name (default `backup`)
3. Configure:
   - “Save-to-backup (real-time)” toggle
   - Optional periodic scan interval in seconds (0 = disabled)
   - File type filters via checkboxes (click “Scan and Add Types” to auto-discover missing extensions from the source)
4. Click “Save Config”, then “Start Monitoring”.
5. Watch progress and recent operations in the status area.

## How It Works
- Watchdog monitors create/modify/delete/move events from your source directory.
- A single worker thread processes events sequentially (ensures order and consistency).
- Copies are chunked with a progress bar for large files.
- On startup:
  - If both targets already contain the backup subfolder, the app enqueues only files that differ (size or mtime) for incremental sync.
  - If either target is missing the subfolder, the app enqueues an initial backup of all eligible files.

## Configuration Details
- Source folder: root of the files you edit (thesis, figures, code)
- OneDrive target: must be your local OneDrive sync path, not a cloud URL
- Local target: any writable local drive or folder
- Target subfolder: files are mirrored under this subfolder (default `backup`)
- Save-to-backup:
  - ON: enqueue on file save/create immediately
  - OFF: rely on periodic scan or manual “recent changes” scan
- File type filters:
  - Preloaded with common doc/code extensions (docx, pdf, txt, md, py, js, etc.)
  - Add new extensions via “Scan and Add Types”
- Exclusions (not backed up):
  - Folders: `node_modules`, `vendor`, `__pycache__`, `site-packages`, and similar build/cache directories
  - Files: `.pyc`, etc.
  - Office temp files: `~$*.docx`, `~$*.xlsx`

## Logging
- Location: `backup/logs/backup-YYYY-MM-DD.jsonl`
- Format: JSON per line including timestamp, action, path, size, hash, status, and error message (if any)
- Rotation: one file per day
- Retention: last 7 days; older logs auto-removed
- Fallback: if log write fails, entries go to `backup/logs/fallback-errors.jsonl`

## Conflict Resolution
- When a destination file already exists and hashes differ, the new copy is saved as:
  ```
  <name><ext>.conflict-YYYYMMDD-HHMMSS
  ```
- This prevents accidental overwrites and preserves both versions.

## Troubleshooting
- Permission errors:
  - The app checks write access at startup by creating and removing a tiny test file in each target subfolder
  - If you see permission warnings, run with sufficient rights or choose a different location/drive
- Space checks:
  - The app checks local disk space of the drive root (OneDrive uses local storage before cloud sync)
  - Ensure the local drive hosting your OneDrive folder has enough free space
- Finding drives:
  - Use “Select Local Drive” to pick a drive letter quickly (e.g., `D:\`)
- Office temp files:
  - `~$*.docx` and `~$*.xlsx` are ignored by design, so backups happen when the real file is saved

## Notes
- Everything runs offline; no cloud API calls
- Backups preserve your source directory hierarchy under the `backup` subfolder in each target
- Real-time monitoring is ideal for thesis/coding workflows with frequent small saves

## License
Personal use. Adapt as needed for your workflow.

