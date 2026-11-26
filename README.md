# Microsoft Outlook Forensic Suite

A standalone digital forensics tool for parsing, decoding, analyzing, and viewing **Microsoft Outlook** artifacts — including **New Outlook for Windows (`Olk` / WebView2 LevelDB & IndexedDB)**, **Classic Outlook `.ost` & `.pst` files**, and **standalone `.msg`, `.eml`, & `.mbox` files**.

Each investigation is organized into its own self-contained, portable **case** folder with an interactive **Outlook 365 desktop UI**, reconstructed **Mail Chains (conversation threads)**, lossless **attachment extraction** with SHA-256 verification, full RFC 5322 & MAPI metadata inspection, and CSV reports.

> Runs 100% offline. The built-in web server binds to `127.0.0.1` only, and no data leaves the machine.

---

## Features

- **Multi-Source Outlook Ingestion:**
  - **New Outlook (`Olk` / WebView2 LevelDB & IndexedDB):** Parses `.ldb` and `.log` files directly using an embedded Chromium IndexedDB & LevelDB engine (`dfindexeddb` + `cramjam` Snappy/Zstd bindings), plus `Local Storage\leveldb`, `Session Storage`, `Sync Data\LevelDB`, `UserSettings.json`, `xpdApi.log`, and `logs/olk_*.log`.
  - **Classic Outlook `.ost` & `.pst` Files:** Parses the full PFF folder tree, MAPI `record_sets` (`PR_*` tags), recipient tables, HTML/Plain/RTF bodies, binary attachments, and `[Recovered Orphan Items]` via `pypff` (with a raw carving fallback for damaged files).
  - **Standalone `.msg`, `.eml`, & `.mbox` Files:** Decodes OLE2 `.msg` compounds and RFC 5322 MIME emails (including RFC 2047 encoded headers, Quoted-Printable, Base64, UTF-8, UTF-16LE, CP1252).
- **Accurate Mail Chain (Conversation Thread) Reconstruction:**
  - Groups emails into chronological mail chains using a Multi-Signal Union-Find algorithm across:
    1. Explicit `ConversationId` (New Outlook IndexedDB / EWS / MAPI `0x3013`)
    2. MAPI `ConversationIndex` 16-byte thread GUID (`PR_CONVERSATION_INDEX` / `0x0071`) and 5-byte response levels
    3. RFC 5322 `Message-ID`, `In-Reply-To`, and `References` dependency graphs
    4. Normalized `ConversationTopic` / `Subject` + participant overlap
- **Lossless Attachment Extraction & Inline CID Rendering:**
  - Writes every attachment unaltered to `<case_dir>/outlook_attachments/`, computes its **SHA-256** integrity hash and exact byte size, and rewrites inline `cid:...` images in HTML email bodies so they render directly inside the email chain.
- **Clear Outlook 365 3-Pane UI:**
  - **Pane 1:** Mailbox Folders tree (`All Mailboxes`, `Inbox`, `Sent Items`, `Drafts`, `Deleted Items`, `Archive`, `Junk Email`, `[Recovered Orphan Items]`, custom folders).
  - **Pane 2:** Mail Chains list with thread message counts, attachment badges, sender avatars, quick filters (`Chains 2+`, `Attachments`, `High Priority`, `Deleted`, `Unread`), and a toggle between **Grouped Mail Chains** and **Flat Messages**.
  - **Pane 3:** Mail Chain Reading Pane with chain attachment summary bar, stacked email cards, thread connectors, reply depth indicators, full `From` / `To` / `Cc` / `Bcc` / `Reply-To` envelope headers, dual timestamps (`IST` + `UTC`), attachment preview modal, and per-message `Rich Email View` | `Unaltered Plain Text` | `Headers & Forensic Metadata` tabs.
  - **Additional Modules:** Global Search & Distinct Token Cloud, Attachments Center, Calendar & Meetings, Contacts & People Directory, Raw LevelDB & Olk Inspector, and Case Audit Overview.

---

## Installation

```bash
pip install -r requirements.txt
pip install --no-deps dfindexeddb
```

## Usage

### 1. Interactive Desktop Window (Default)
```bash
python outlook_forensic_tool.py
```

### 2. Direct Command-Line Extraction
```bash
python outlook_forensic_tool.py "%LOCALAPPDATA%\Microsoft\Olk" --case NewOutlook_Audit --no-browser
python outlook_forensic_tool.py "C:\Evidence\custodian_mailbox.pst" --case Custodian_PST --no-browser
```

---

## Output Structure

Everything for a case is written to `cases/<CaseName>/`:

```
cases/
└── <CaseName>/
    ├── Outlook_Forensic_Viewer.html            # Standalone interactive Outlook 365 UI (works offline via file://)
    ├── Outlook_Mail_Chains_Summary.csv         # Reconstructed mail chains & thread statistics
    ├── Outlook_Messages_Complete.csv           # Every email message with full headers, bodies & thread links
    ├── Outlook_Attachments_Catalog.csv         # Attachment manifest with SHA-256 hashes & exact sizes
    ├── Outlook_Calendar_Meetings.csv           # Calendar appointments & meeting requests
    ├── Outlook_Contacts_Directory.csv          # Address book contacts & email correspondents
    ├── Outlook_LevelDB_Forensic_Records.csv    # Raw decoded LevelDB / IndexedDB / Olk LocalStorage records
    ├── Case_Audit_Summary.txt                  # Forensic audit report
    └── outlook_attachments/                    # Unaltered extracted binary attachments & inline CID media
```
