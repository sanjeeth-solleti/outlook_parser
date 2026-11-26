"""
MICROSOFT OUTLOOK FORENSIC SUITE - CASE EDITION & DESKTOP WINDOW
================================================================
A standalone digital forensics tool for parsing, decoding, analyzing, and viewing
Microsoft Outlook artifacts — including New Outlook (Olk / WebView2 LevelDB & IndexedDB),
Classic Outlook OST & PST files, standalone MSG & EML/MBOX files — organized into
dedicated investigation cases with a clear Outlook 365 UI, reconstructed mail chains,
and lossless attachment extraction.

Launcher: `python outlook_forensic_tool.py`
"""

import os
import sys
import io
import json
import csv
import re
import shutil
import zipfile
import base64
import html
import hashlib
import datetime
import pathlib
import struct
import threading
import time
import webbrowser
import subprocess
import logging
import quopri
import email
import email.policy
import email.utils
import email.header
import mailbox
from collections import defaultdict, Counter
from flask import Flask, request, jsonify, send_file, render_template_string, redirect

# Increase CSV field limit for large forensic email payloads
csv.field_size_limit(2147483647)

TOOL_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.abspath(os.path.join(TOOL_DIR, ".."))
CASES_DIR = os.path.join(TOOL_DIR, "cases")

def get_default_outlook_paths():
    candidates = [
        os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Olk\EBWebView\Default\IndexedDB"),
        os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Olk\EBWebView\Default"),
        os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Olk"),
        os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Outlook"),
        os.path.expanduser(r"~\Documents\Outlook Files"),
        os.path.expandvars(r"%APPDATA%\Microsoft\Outlook"),
        os.getcwd(),
        os.path.expanduser("~")
    ]
    # Also check Packages\Microsoft.OutlookForWindows_*
    pkg_root = os.path.expandvars(r"%LOCALAPPDATA%\Packages")
    if os.path.exists(pkg_root):
        try:
            for d in os.listdir(pkg_root):
                if "outlookforwindows" in d.lower():
                    candidates.insert(0, os.path.join(pkg_root, d, "LocalCache", "Microsoft", "Olk"))
                    candidates.insert(0, os.path.join(pkg_root, d))
        except Exception:
            pass
    return [c for c in candidates if c and os.path.exists(c)]

def native_folder_picker():
    try:
        import tkinter as tk
        from tkinter import filedialog
        root = tk.Tk()
        root.withdraw()
        root.wm_attributes("-topmost", 1)
        cands = get_default_outlook_paths()
        start_dir = cands[0] if cands else os.getcwd()
        folder = filedialog.askdirectory(
            title="Select Microsoft Outlook Evidence Folder (Olk LevelDB/IndexedDB or PST/OST Folder)",
            initialdir=start_dir or None
        )
        root.destroy()
        return folder if folder else None
    except Exception as e:
        print("[Folder Picker Error]", e)
        return None

def native_file_picker():
    try:
        import tkinter as tk
        from tkinter import filedialog
        root = tk.Tk()
        root.withdraw()
        root.wm_attributes("-topmost", 1)
        cands = [
            os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Outlook"),
            os.path.expanduser(r"~\Documents\Outlook Files"),
            os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Olk"),
            os.getcwd()
        ]
        start_dir = next((c for c in cands if c and os.path.exists(c)), os.getcwd())
        fpath = filedialog.askopenfilename(
            title="Select Outlook Data File (OST, PST, MSG, EML, MBOX, LDB, LOG)",
            initialdir=start_dir or None,
            filetypes=[
                ("Outlook Forensic Files", "*.ost *.pst *.msg *.eml *.mbox *.ldb *.log *.json *.csv"),
                ("Outlook OST/PST Files", "*.ost *.pst"),
                ("Email Message Files", "*.msg *.eml *.mbox"),
                ("LevelDB Files", "*.ldb *.log"),
                ("All Files", "*.*")
            ]
        )
        root.destroy()
        return fpath if fpath else None
    except Exception as e:
        print("[File Picker Error]", e)
        return None

def get_latest_case():
    if not os.path.exists(CASES_DIR):
        return None
    candidates = [d for d in os.listdir(CASES_DIR) if os.path.isdir(os.path.join(CASES_DIR, d))]
    if not candidates:
        return None
    candidates.sort(key=lambda d: os.path.getmtime(os.path.join(CASES_DIR, d)), reverse=True)
    return candidates[0]

app = Flask(__name__)

@app.after_request
def add_no_cache_headers(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

app.config['MAX_CONTENT_LENGTH'] = 4 * 1024 * 1024 * 1024  # 4 GB max upload

active_case_initial = get_latest_case() or ""
parsing_status = {
    "running": False,
    "stage": "Idle",
    "progress": 0,
    "logs": [],
    "stats": {},
    "active_case": active_case_initial,
    "case_dir": os.path.join(CASES_DIR, active_case_initial) if active_case_initial else None,
    "error": None,
    "completed": False
}

# Preload existing case stats if present
if active_case_initial:
    viewer_file = os.path.join(CASES_DIR, active_case_initial, "Outlook_Forensic_Viewer.html")
    if os.path.exists(viewer_file):
        try:
            with open(viewer_file, "r", encoding="utf-8", errors="ignore") as vf:
                head = vf.read(180000)
            m_stats = re.search(r'"stats":\s*({.*?})\s*,\s*"mail_chains"', head, re.DOTALL)
            if not m_stats:
                m_stats = re.search(r'"stats":\s*({[^}]+})', head)
            if m_stats:
                parsing_status["stats"] = json.loads(m_stats.group(1))
                parsing_status["completed"] = True
                parsing_status["progress"] = 100
                parsing_status["logs"] = [f"[System] Active case loaded: {active_case_initial} ({parsing_status['case_dir']})"]
        except Exception:
            pass

def log_progress(msg, progress=None):
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    formatted = f"[{timestamp}] {msg}"
    print(formatted)
    parsing_status["logs"].append(formatted)
    if progress is not None:
        parsing_status["progress"] = progress

def decode_mime_words(s):
    """Decodes RFC 2047 encoded words (e.g. =?utf-8?B?...?= or =?iso-8859-1?Q?...?=) without altering clean text."""
    if not s:
        return ""
    if not isinstance(s, str):
        try:
            s = bytes(s).decode("utf-8", errors="replace")
        except Exception:
            s = str(s)
    if "=?" not in s:
        return s
    try:
        parts = email.header.decode_header(s)
        decoded_fragments = []
        for frag, enc in parts:
            if isinstance(frag, bytes):
                charset = enc or "utf-8"
                try:
                    decoded_fragments.append(frag.decode(charset, errors="replace"))
                except LookupError:
                    decoded_fragments.append(frag.decode("utf-8", errors="replace"))
            else:
                decoded_fragments.append(str(frag))
        return "".join(decoded_fragments)
    except Exception:
        return s

def safe_decode_bytes(raw_bytes, preferred_encoding=None):
    """Losslessly converts byte sequences to string across UTF-8, UTF-16LE, CP1252, and Latin-1."""
    if raw_bytes is None:
        return ""
    if isinstance(raw_bytes, str):
        return raw_bytes
    if not isinstance(raw_bytes, (bytes, bytearray, memoryview)):
        return str(raw_bytes)
    b = bytes(raw_bytes)
    if not b:
        return ""
    # Check BOMs first
    if b.startswith(b"\xff\xfe"):
        try:
            return b[2:].decode("utf-16-le", errors="replace")
        except Exception:
            pass
    elif b.startswith(b"\xfe\xff"):
        try:
            return b[2:].decode("utf-16-be", errors="replace")
        except Exception:
            pass
    elif b.startswith(b"\xef\xbb\xbf"):
        try:
            return b[3:].decode("utf-8", errors="replace")
        except Exception:
            pass
    # Check if HTML meta charset is declared
    if not preferred_encoding and b"charset=" in b[:2048].lower():
        m = re.search(rb'charset=["\']?([a-zA-Z0-9_\-]+)', b[:2048], re.IGNORECASE)
        if m:
            try:
                preferred_encoding = m.group(1).decode("ascii", errors="ignore")
            except Exception:
                pass
    encodings = []
    if preferred_encoding:
        encodings.append(preferred_encoding)
    # Detect interleaved nulls typical of UTF-16LE in MAPI/LevelDB
    if len(b) >= 4 and b[1::2].count(0) > len(b) * 0.35:
        encodings.append("utf-16-le")
    encodings.extend(["utf-8", "cp1252", "iso-8859-1"])
    for enc in encodings:
        try:
            return b.decode(enc)
        except Exception:
            continue
    return b.decode("utf-8", errors="replace")

def format_time(val):
    """Normalizes any timestamp (ISO, RFC 2822, Unix epoch s/ms/us, Windows FILETIME, datetime) into (time_utc, time_local_ist, sort_iso)."""
    if val is None or val in ("", "<undefined>", "<null>", "None", 0, "0"):
        return "", "", ""
    try:
        dt = None
        if isinstance(val, datetime.datetime):
            dt = val
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=datetime.timezone.utc)
            else:
                dt = dt.astimezone(datetime.timezone.utc)
        elif isinstance(val, (int, float)):
            fval = float(val)
            if fval <= 0:
                return "", "", ""
            # Windows FILETIME (100-ns intervals since 1601-01-01): > 1e16
            if fval > 1e16:
                unix_sec = (fval - 116444736000000000.0) / 10000000.0
                dt = datetime.datetime.fromtimestamp(unix_sec, datetime.timezone.utc)
            # Microseconds epoch: 1e13 .. 1e16
            elif fval > 1e13:
                dt = datetime.datetime.fromtimestamp(fval / 1000000.0, datetime.timezone.utc)
            # Milliseconds epoch: 1e11 .. 1e13
            elif fval > 1e11:
                dt = datetime.datetime.fromtimestamp(fval / 1000.0, datetime.timezone.utc)
            else:
                dt = datetime.datetime.fromtimestamp(fval, datetime.timezone.utc)
        elif isinstance(val, str):
            s = val.strip()
            if not s:
                return "", "", ""
            if s.isdigit() or (s.replace(".", "", 1).isdigit() and s.count(".") <= 1):
                return format_time(float(s))
            # Try ISO-8601 first
            try:
                iso_s = s.replace("Z", "+00:00")
                dt = datetime.datetime.fromisoformat(iso_s)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=datetime.timezone.utc)
                else:
                    dt = dt.astimezone(datetime.timezone.utc)
            except Exception:
                pass
            # Try RFC 2822 / Email Date header (e.g. "Wed, 13 May 2026 09:04:13 GMT")
            if dt is None:
                try:
                    dt = email.utils.parsedate_to_datetime(s)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=datetime.timezone.utc)
                    else:
                        dt = dt.astimezone(datetime.timezone.utc)
                except Exception:
                    pass
            # Try common log formats (MM/DD/YYYY HH:MM:SS or YYYY-MM-DD HH:MM:SS)
            if dt is None:
                for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%m/%d/%Y %H:%M:%S", "%d-%m-%Y %H:%M:%S"):
                    try:
                        dt = datetime.datetime.strptime(s[:26], fmt).replace(tzinfo=datetime.timezone.utc)
                        break
                    except Exception:
                        continue
        if dt is not None:
            # Guard against out-of-range bogus dates (e.g. year 1601 empty FILETIME)
            if dt.year <= 1970:
                return "", "", ""
            dt_ist = dt + datetime.timedelta(hours=5, minutes=30)
            utc_str = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
            ist_str = dt_ist.strftime("%Y-%m-%d %H:%M:%S")
            sort_str = dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            return utc_str, ist_str, sort_str
    except Exception:
        pass
    s_val = str(val).strip()
    return s_val, s_val, s_val

def parse_mapi_conversation_index(conv_idx_raw):
    """
    Decodes Microsoft MAPI ConversationIndex (PR_CONVERSATION_INDEX / 0x0071).
    Structure:
      - 22-byte header:
        - Byte 0: Reserved (0x01)
        - Bytes 1..5: 40-bit FILETIME timestamp
        - Bytes 6..21: 16-byte GUID uniquely identifying the mail thread/chain
      - Followed by N * 5-byte child response levels (reply hierarchy & time deltas).
    Returns dict with: hex, thread_guid, reply_depth, header_time_utc, level_timestamps
    """
    if not conv_idx_raw:
        return {"hex": "", "thread_guid": "", "reply_depth": 0, "header_time_utc": ""}
    raw_bytes = None
    if isinstance(conv_idx_raw, (bytes, bytearray, memoryview)):
        raw_bytes = bytes(conv_idx_raw)
    elif isinstance(conv_idx_raw, str):
        s = conv_idx_raw.strip()
        # Check if hex string
        if re.fullmatch(r'[0-9a-fA-F]+', s) and len(s) >= 44 and len(s) % 2 == 0:
            try:
                raw_bytes = bytes.fromhex(s)
            except Exception:
                pass
        if raw_bytes is None:
            # Try base64
            try:
                dec = base64.b64decode(s)
                if len(dec) >= 22:
                    raw_bytes = dec
            except Exception:
                pass
    if not raw_bytes or len(raw_bytes) < 22:
        hex_str = raw_bytes.hex() if raw_bytes else str(conv_idx_raw)
        return {"hex": hex_str, "thread_guid": "", "reply_depth": 0, "header_time_utc": ""}

    hex_str = raw_bytes.hex()
    guid_bytes = raw_bytes[6:22]
    thread_guid = guid_bytes.hex().lower()
    rem = len(raw_bytes) - 22
    reply_depth = max(0, rem // 5)

    # Decode 40-bit FILETIME in bytes 1..6 (big-endian high 40 bits of 64-bit FILETIME)
    header_time_utc = ""
    try:
        ft_high40 = int.from_bytes(raw_bytes[1:6], byteorder="big")
        ft_64 = ft_high40 << 24
        u_str, _, _ = format_time(ft_64)
        header_time_utc = u_str
    except Exception:
        pass

    return {
        "hex": hex_str,
        "thread_guid": thread_guid,
        "reply_depth": reply_depth,
        "header_time_utc": header_time_utc
    }

def normalize_subject(subj):
    """Strips Re:, Fwd:, FW:, AW:, WG:, [External], etc. to find canonical thread topic."""
    if not subj:
        return "(No Subject)"
    s = decode_mime_words(str(subj)).strip()
    s = re.sub(r'\s+', ' ', s)
    # Iteratively strip prefixes like Re:, RE[2]:, Fwd:, FW:, [EXTERNAL], [EXT]
    pattern = re.compile(
        r'^(?:(?:re|fw|fwd|aw|wg|sv|vs)(?:\[\d+\]|\(\d+\))?\s*:\s*|\[(?:external|ext|spam|phish|quarantine|secure)[^\]]*\]\s*)+',
        re.IGNORECASE
    )
    cleaned = pattern.sub('', s).strip()
    return cleaned if cleaned else (s or "(No Subject)")

def parse_email_address_list(raw_val):
    """
    Normalizes any recipient representation (EWS Mailbox dict, Graph emailAddress dict,
    list of dicts, or RFC 5322 address string) into a list of {'name': ..., 'email': ..., 'display': ...}.
    """
    if not raw_val:
        return []
    results = []

    def add_entry(name_str, email_str):
        n = decode_mime_words(str(name_str or "")).strip().strip('"').strip("'")
        e = decode_mime_words(str(email_str or "")).strip().strip('<').strip('>')
        # Clean Exchange LegacyDN if an SMTP address is embedded, otherwise preserve LegacyDN
        if not n and not e:
            return
        if "@" in n and not e:
            e = n
        if not n and e:
            if "@" in e:
                user_part = e.split("@")[0]
                parts = [p.capitalize() for p in re.split(r'[._\-]+', user_part) if p]
                n = " ".join(parts) if parts else e
            elif "/cn=" in e.lower():
                cn_part = e.split("=")[-1]
                n = re.sub(r'^[0-9a-fA-F]{32}-?', '', cn_part).strip() or e
            else:
                n = e
        disp = f"{n} <{e}>" if (n and e and n.lower() != e.lower()) else (e or n)
        results.append({"name": n, "email": e.lower() if "@" in e else e, "display": disp})

    if isinstance(raw_val, dict):
        # Graph: {"emailAddress": {"name": ..., "address": ...}}
        # EWS/OWA: {"Mailbox": {"Name": ..., "EmailAddress": ...}} or {"Name": ..., "EmailAddress": ...}
        inner = raw_val.get("emailAddress") or raw_val.get("Mailbox") or raw_val.get("mailbox") or raw_val
        if isinstance(inner, dict):
            name = inner.get("name") or inner.get("Name") or inner.get("displayName") or inner.get("DisplayName") or ""
            addr = inner.get("address") or inner.get("Address") or inner.get("emailAddress") or inner.get("EmailAddress") or inner.get("email") or inner.get("Email") or inner.get("smtpAddress") or ""
            if name or addr:
                add_entry(name, addr)
                return results
        # If dict of multiple keys
        for v in raw_val.values():
            if isinstance(v, (dict, list)):
                results.extend(parse_email_address_list(v))
        return results

    if isinstance(raw_val, (list, tuple, set)):
        for item in raw_val:
            results.extend(parse_email_address_list(item))
        return results

    if isinstance(raw_val, str):
        s = decode_mime_words(raw_val).strip()
        if not s or s in ("<undefined>", "<null>", "None"):
            return []
        if s.startswith("[") or s.startswith("{"):
            try:
                parsed = json.loads(s)
                return parse_email_address_list(parsed)
            except Exception:
                pass
        try:
            addrs = email.utils.getaddresses([s])
            for realname, addr in addrs:
                if realname or addr:
                    add_entry(realname, addr)
            if results:
                return results
        except Exception:
            pass
        add_entry("", s)
    return results

def html_to_plain_text(html_str):
    """Converts HTML email body into clean readable plain text without losing content."""
    if not html_str:
        return ""
    s = str(html_str)
    # Remove <style> and <script> blocks
    s = re.sub(r'<(style|script)[^>]*>.*?</\1>', ' ', s, flags=re.DOTALL | re.IGNORECASE)
    # Convert block breaks to newlines
    s = re.sub(r'<br\s*/?>', '\n', s, flags=re.IGNORECASE)
    s = re.sub(r'</(p|div|tr|li|h[1-6]|blockquote)>', '\n', s, flags=re.IGNORECASE)
    s = re.sub(r'<td[^>]*>', '\t', s, flags=re.IGNORECASE)
    s = re.sub(r'<[^>]+>', '', s)
    s = html.unescape(s)
    lines = [re.sub(r'[ \t]+', ' ', ln).strip() for ln in s.splitlines()]
    cleaned = "\n".join(ln for ln in lines if ln)
    return cleaned

def decode_rtf_body(rtf_raw):
    """
    Losslessly decodes MAPI PR_RTF_COMPRESSED (0x1009) or raw RTF streams:
    - Decompresses LZFU ('LZFu' / 'MELA') compressed RTF via compressed_rtf if needed
    - De-encapsulates embedded HTML (\\fromhtml1) or Plain Text (\\fromtext) via RTFDE if present
    - Falls back to clean RTF control-word stripping so plain text is always recovered.
    Returns (rtf_str, extracted_html, extracted_plain).
    """
    if not rtf_raw:
        return "", "", ""
    raw_bytes = rtf_raw.encode("latin-1", errors="replace") if isinstance(rtf_raw, str) else bytes(rtf_raw)
    if len(raw_bytes) >= 16 and raw_bytes[8:12] in (b"LZFu", b"MELA"):
        try:
            import compressed_rtf
            raw_bytes = compressed_rtf.decompress(raw_bytes)
        except Exception:
            pass

    rtf_str = safe_decode_bytes(raw_bytes).rstrip("\x00")
    extracted_html = ""
    extracted_plain = ""

    # Try RTFDE de-encapsulation for HTML-in-RTF (\fromhtml1) or Text-in-RTF (\fromtext)
    if b"\\fromhtml" in raw_bytes or b"\\fromtext" in raw_bytes:
        try:
            from RTFDE.deencapsulate import DeEncapsulator
            deenc = DeEncapsulator(raw_bytes)
            deenc.deencapsulate()
            if deenc.content_type == "html" and deenc.html:
                extracted_html = safe_decode_bytes(deenc.html).strip()
            elif deenc.content_type == "text" and deenc.text:
                extracted_plain = safe_decode_bytes(deenc.text).strip()
        except Exception:
            pass

    if not extracted_plain and rtf_str:
        if extracted_html:
            extracted_plain = html_to_plain_text(extracted_html)
        elif rtf_str.lstrip().startswith("{\\rtf"):
            # Strip fonttbl, colortbl, stylesheet, info groups and RTF control words
            cleaned = re.sub(r'\{\\(?:fonttbl|colortbl|stylesheet|info|\*\\[^a-zA-Z0-9]*[a-zA-Z0-9]+)[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', ' ', rtf_str)
            cleaned = re.sub(r'\\(?:par|pard|line|sect)\b\s?', '\n', cleaned)
            cleaned = re.sub(r'\\tab\b\s?', '\t', cleaned)
            cleaned = re.sub(r"\\'([0-9a-fA-F]{2})", lambda m: bytes.fromhex(m.group(1)).decode("cp1252", errors="replace"), cleaned)
            cleaned = re.sub(r'\\[a-zA-Z]+\-?\d*\s?', '', cleaned)
            cleaned = re.sub(r'[{}]', '', cleaned)
            lines = [re.sub(r'[ \t]+', ' ', ln).strip() for ln in cleaned.splitlines()]
            extracted_plain = "\n".join(ln for ln in lines if ln)

    return rtf_str, extracted_html, extracted_plain

def sanitize_email_html_for_viewer(raw_html, cid_map=None):
    """
    Prepares an HTML email body for lossless display inside the Outlook UI:
    - Rewrites inline cid:... image references to extracted attachment paths
    - Neutralizes document-level <html>/<head>/<body> tags and scopes global CSS selectors
      so an email's stylesheet cannot break the outer Outlook viewer layout
    - Preserves 100% of email text, formatting, tables, colors, links, and quoted history.
    """
    if not raw_html:
        return ""
    h = str(raw_html)
    # Rewrite cid: references if cid_map is provided
    if cid_map:
        def replace_cid(match):
            attr_prefix = match.group(1)
            quote = match.group(2)
            cid_val = match.group(3).strip()
            clean_cid = cid_val.strip("<>").lower()
            clean_cid_short = clean_cid.split("@")[0]
            mapped = cid_map.get(clean_cid) or cid_map.get(clean_cid_short)
            if mapped:
                return f'{attr_prefix}{quote}{mapped}{quote} onclick="openImageModal(this.src)" style="cursor:zoom-in; max-width:100%;"'
            return match.group(0)
        h = re.sub(r'(src\s*=\s*)(["\'])cid:([^"\']+)\2', replace_cid, h, flags=re.IGNORECASE)

    # Strip <script> tags for forensic viewer safety while preserving everything else
    h = re.sub(r'<script[^>]*>.*?</script>', '', h, flags=re.DOTALL | re.IGNORECASE)
    # Neutralize global body/html/:root/universal selectors inside <style> blocks
    def scope_style_block(m):
        css = m.group(1)
        css = re.sub(r'\b(html|body|:root)\b', '.email-render-scope', css, flags=re.IGNORECASE)
        return f"<style>{css}</style>"
    h = re.sub(r'<style[^>]*>(.*?)</style>', scope_style_block, h, flags=re.DOTALL | re.IGNORECASE)
    # Unwrap outer <!DOCTYPE>, <html>, <head>, <body> tags while keeping their inner content
    h = re.sub(r'<!DOCTYPE[^>]*>', '', h, flags=re.IGNORECASE)
    h = re.sub(r'</?(html|head|body|meta|title)[^>]*>', '', h, flags=re.IGNORECASE)
    return h.strip()

def sanitize_idb_value(val):
    if val is None:
        return None
    cls_name = val.__class__.__name__
    if cls_name in ("Undefined", "Null", "NullType", "UndefinedType"):
        return None
    if isinstance(val, (bytes, bytearray, memoryview)):
        return safe_decode_bytes(val)
    if isinstance(val, dict):
        return {str(k): sanitize_idb_value(v) for k, v in val.items()}
    if isinstance(val, (list, tuple, set)):
        return [sanitize_idb_value(x) for x in val]
    if hasattr(val, "__dict__") and not isinstance(val, (str, int, float, bool)):
        try:
            if hasattr(val, "value") and len(val.__dict__) <= 2:
                return sanitize_idb_value(val.value)
            return {str(k): sanitize_idb_value(v) for k, v in val.__dict__.items() if not str(k).startswith("_")}
        except Exception:
            return str(val)
    return val

_NATIVE_INDEXEDDB_PAYLOAD = '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'

def init_native_indexeddb_engine():
    """Initializes the built-in Chromium IndexedDB / LevelDB decoding engine."""
    import sys, types, zlib, json, base64

    # Setup Snappy and Zstandard decompression bindings via cramjam
    try:
        import cramjam
        snappy_mod = types.ModuleType("snappy")
        snappy_mod.decompress = lambda d: bytes(cramjam.snappy.decompress_raw(d))
        snappy_mod.compress = cramjam.snappy.compress_raw
        snappy_mod.uncompress = lambda d: bytes(cramjam.snappy.decompress_raw(d))
        sys.modules["snappy"] = snappy_mod

        zstd_mod = types.ModuleType("zstd")
        zstd_mod.decompress = lambda d: bytes(cramjam.zstd.decompress(d))
        zstd_mod.compress = cramjam.zstd.compress
        sys.modules["zstd"] = zstd_mod
    except Exception:
        pass

    if "dfindexeddb.indexeddb.chromium.record" not in sys.modules:
        try:
            bundle = json.loads(zlib.decompress(base64.b64decode(_NATIVE_INDEXEDDB_PAYLOAD)).decode("utf-8"))
            for mod_name, code in bundle:
                m = types.ModuleType(mod_name)
                m.__file__ = f"<native:{mod_name}>"
                if not code:
                    m.__path__ = []
                sys.modules[mod_name] = m
                if "." in mod_name:
                    parent, child = mod_name.rsplit(".", 1)
                    setattr(sys.modules[parent], child, m)
                if code:
                    exec(compile(code, f"<native:{mod_name}>", "exec"), m.__dict__)
        except Exception as e:
            log_progress(f"  Note: Native IndexedDB engine initialization notice: {e}")
            return None, None, None

    try:
        chromium_rec = sys.modules["dfindexeddb.indexeddb.chromium.record"].ChromiumIndexedDBRecord
        ldb_rec = sys.modules["dfindexeddb.leveldb.record"].LevelDBRecord
        ldb_folder = sys.modules["dfindexeddb.leveldb.record"].FolderReader
        return chromium_rec, ldb_rec, ldb_folder
    except Exception as e:
        log_progress(f"  Note: Native LevelDB class resolution notice: {e}")
        return None, None, None


class OutlookForensicEngine:
    def __init__(self, target_path, case_name=None, output_dir=None):
        self.target_path = os.path.abspath(target_path)
        base_name = os.path.basename(self.target_path.rstrip(r"\/"))
        if not case_name:
            clean_base = re.sub(r'[^a-zA-Z0-9_-]', '_', os.path.splitext(base_name)[0] or "Outlook")
            time_tag = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            self.case_name = f"Case_{clean_base}_{time_tag}"
        else:
            self.case_name = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', case_name.strip())

        self.case_dir = output_dir or os.path.join(CASES_DIR, self.case_name)
        os.makedirs(self.case_dir, exist_ok=True)
        self.output_dir = self.case_dir

        self.attachments_dir = os.path.join(self.case_dir, "outlook_attachments")
        os.makedirs(self.attachments_dir, exist_ok=True)

        parsing_status["active_case"] = self.case_name
        parsing_status["case_dir"] = self.case_dir

        self.primary_user = "Outlook Account"
        self.primary_email = ""
        self.primary_tenant = "Microsoft Outlook"
        self.account_identities = []

        # Raw ingested collections
        self.messages_raw = []
        self.conv_meta_raw = {}
        self.folders_map = {}
        self.calendar_raw = []
        self.contacts_raw = []
        self.leveldb_records = []
        self.source_files_ingested = []

        # Processed & normalized collections
        self.messages_by_key = {}
        self.all_messages_list = []
        self.mail_chains = []
        self.mail_chains_map = {}
        self.attachments_catalog = []
        self.seen_attachment_filenames = set()
        self.clean_meetings = []
        self.contacts_dict = {}
        self.clean_contacts = []
        self.folder_stats = defaultdict(lambda: {"total": 0, "unread": 0, "chains": 0})

    def compute_sha256(self, data_bytes):
        if not data_bytes:
            return ""
        return hashlib.sha256(data_bytes).hexdigest()

    def detect_mime_and_ext(self, data_bytes, filename=""):
        ext = os.path.splitext(filename)[1].lower() if filename else ""
        if data_bytes and len(data_bytes) >= 4:
            if data_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
                return "image/png", ext or ".png", "Image"
            if data_bytes.startswith(b"\xff\xd8\xff"):
                return "image/jpeg", ext or ".jpg", "Image"
            if data_bytes.startswith(b"GIF87a") or data_bytes.startswith(b"GIF89a"):
                return "image/gif", ext or ".gif", "Image"
            if data_bytes.startswith(b"RIFF") and b"WEBP" in data_bytes[:32]:
                return "image/webp", ext or ".webp", "Image"
            if data_bytes.startswith(b"BM"):
                return "image/bmp", ext or ".bmp", "Image"
            if data_bytes.startswith(b"%PDF-"):
                return "application/pdf", ext or ".pdf", "PDF Document"
            if data_bytes.startswith(b"PK\x03\x04"):
                if ext in (".docx", ".xlsx", ".pptx"):
                    cat = {".docx": "Word Document", ".xlsx": "Spreadsheet", ".pptx": "Presentation"}[ext]
                    return "application/vnd.openxmlformats", ext, cat
                return "application/zip", ext or ".zip", "Archive"
            if data_bytes.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
                if ext in (".doc", ".xls", ".ppt", ".msg"):
                    cat = {".doc": "Word Document", ".xls": "Spreadsheet", ".ppt": "Presentation", ".msg": "Outlook Message"}[ext]
                    return "application/x-ole-storage", ext, cat
                return "application/x-ole-storage", ext or ".bin", "OLE2 Document"

        ext_map = {
            ".pdf": ("application/pdf", "PDF Document"),
            ".docx": ("application/vnd.openxmlformats-officedocument.wordprocessingml.document", "Word Document"),
            ".doc": ("application/msword", "Word Document"),
            ".xlsx": ("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "Spreadsheet"),
            ".xls": ("application/vnd.ms-excel", "Spreadsheet"),
            ".csv": ("text/csv", "Spreadsheet"),
            ".pptx": ("application/vnd.openxmlformats-officedocument.presentationml.presentation", "Presentation"),
            ".ppt": ("application/vnd.ms-powerpoint", "Presentation"),
            ".txt": ("text/plain", "Text Document"),
            ".log": ("text/plain", "Log File"),
            ".json": ("application/json", "JSON Data"),
            ".xml": ("application/xml", "XML Document"),
            ".html": ("text/html", "HTML Document"),
            ".htm": ("text/html", "HTML Document"),
            ".png": ("image/png", "Image"),
            ".jpg": ("image/jpeg", "Image"),
            ".jpeg": ("image/jpeg", "Image"),
            ".gif": ("image/gif", "Image"),
            ".webp": ("image/webp", "Image"),
            ".bmp": ("image/bmp", "Image"),
            ".svg": ("image/svg+xml", "Image"),
            ".zip": ("application/zip", "Archive"),
            ".7z": ("application/x-7z-compressed", "Archive"),
            ".rar": ("application/x-rar-compressed", "Archive"),
            ".msg": ("application/vnd.ms-outlook", "Outlook Message"),
            ".eml": ("message/rfc822", "Email Message"),
            ".ics": ("text/calendar", "Calendar Invite"),
            ".mp4": ("video/mp4", "Video"),
            ".mp3": ("audio/mpeg", "Audio"),
            ".wav": ("audio/wav", "Audio"),
            ".exe": ("application/x-msdownload", "Executable"),
        }
        if ext in ext_map:
            return ext_map[ext][0], ext, ext_map[ext][1]
        return "application/octet-stream", ext or ".bin", "Attachment"

    def save_attachment_bytes(self, orig_filename, data_bytes, content_type="", content_id="", is_inline=False, msg_meta=None):
        """
        Saves raw attachment bytes to case_dir/outlook_attachments/ without altering a single byte.
        Computes SHA-256 and returns the complete attachment metadata dictionary.
        """
        msg_meta = msg_meta or {}
        det_mime, det_ext, category = self.detect_mime_and_ext(data_bytes, orig_filename)
        final_mime = content_type if (content_type and content_type != "application/octet-stream") else det_mime

        clean_orig = decode_mime_words(str(orig_filename or "")).strip()
        if not clean_orig:
            clean_orig = f"attachment_{len(self.attachments_catalog) + 1}{det_ext}"
        safe_base = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', os.path.basename(clean_orig)).strip(" .")
        if not safe_base:
            safe_base = f"attachment_{len(self.attachments_catalog) + 1}{det_ext}"
        if not os.path.splitext(safe_base)[1] and det_ext:
            safe_base += det_ext

        sha256_hex = self.compute_sha256(data_bytes) if data_bytes else ""
        size_bytes = len(data_bytes) if data_bytes is not None else int(msg_meta.get("declared_size") or 0)

        out_name = safe_base
        out_path = os.path.join(self.attachments_dir, out_name)

        # Deduplicate filename on disk if different content shares the same filename
        if out_name.lower() in self.seen_attachment_filenames:
            existing_sha = ""
            if os.path.exists(out_path) and data_bytes:
                try:
                    with open(out_path, "rb") as ef:
                        existing_sha = self.compute_sha256(ef.read())
                except Exception:
                    pass
            if existing_sha != sha256_hex or not sha256_hex:
                stem, ext_part = os.path.splitext(safe_base)
                suffix = sha256_hex[:8] if sha256_hex else str(len(self.attachments_catalog) + 1)
                out_name = f"{stem}_{suffix}{ext_part}"
                out_path = os.path.join(self.attachments_dir, out_name)

        self.seen_attachment_filenames.add(out_name.lower())

        extracted = False
        if data_bytes is not None and len(data_bytes) > 0:
            try:
                if not os.path.exists(out_path):
                    with open(out_path, "wb") as fout:
                        fout.write(data_bytes)
                extracted = True
            except Exception as e:
                log_progress(f"  Warning saving attachment {out_name}: {e}")

        clean_cid = str(content_id or "").strip().strip("<>")
        att_rec = {
            "att_id": f"att_{len(self.attachments_catalog) + 1}",
            "fileName": clean_orig,
            "savedName": out_name,
            "rel_path": f"outlook_attachments/{out_name}" if extracted else "",
            "contentType": final_mime,
            "category": category,
            "size": size_bytes,
            "sha256": sha256_hex,
            "contentId": clean_cid,
            "isInline": bool(is_inline or clean_cid),
            "extracted": extracted,
            "msg_id": str(msg_meta.get("msg_id") or ""),
            "chain_id": str(msg_meta.get("chain_id") or ""),
            "subject": str(msg_meta.get("subject") or ""),
            "sender": str(msg_meta.get("sender") or ""),
            "time_local": str(msg_meta.get("time_local") or ""),
            "folder": str(msg_meta.get("folder") or ""),
            "source_file": str(msg_meta.get("source_file") or "")
        }
        self.attachments_catalog.append(att_rec)
        return att_rec

    def normalize_folder_name(self, raw_folder, folder_id=""):
        if folder_id and str(folder_id) in self.folders_map:
            mapped = self.folders_map[str(folder_id)].get("name")
            if mapped:
                raw_folder = mapped
        f = str(raw_folder or "").strip().replace("\\", "/")
        # Strip standard PFF root prefixes
        for prefix in ("Top of Personal Folders/", "Top of Outlook data file/", "Top of Information Store/", "Root - Mailbox/", "IPM_SUBTREE/", "Root/"):
            if f.lower().startswith(prefix.lower()):
                f = f[len(prefix):]
        f = f.strip("/")
        if not f:
            return "Inbox"
        fl = f.lower()
        if fl in ("inbox", "mail/inbox", "messages/inbox"):
            return "Inbox"
        if fl in ("sent items", "sent", "sentmessages", "sent mail"):
            return "Sent Items"
        if fl in ("deleted items", "trash", "deletedmessages", "deleted"):
            return "Deleted Items"
        if fl in ("drafts", "draft"):
            return "Drafts"
        if fl in ("junk email", "junk", "spam", "junkemail"):
            return "Junk Email"
        if fl in ("archive", "archives"):
            return "Archive"
        if fl in ("outbox",):
            return "Outbox"
        return f

    def run_pipeline(self):
        log_progress("Step 1/6: Discovering & ingesting Outlook LevelDB, IndexedDB, OST, PST, MSG & EML sources...", 15)
        self.ingest_all_sources()

        log_progress("Step 2/6: Correlating accounts, contacts directory & folder hierarchy...", 35)
        self.process_contacts_and_accounts()

        log_progress("Step 3/6: Decoding & normalizing email messages, headers, bodies & attachments...", 55)
        self.process_messages()

        log_progress("Step 4/6: Extracting cached attachments & linking inline CID media...", 72)
        self.extract_cached_media_and_link_cids()

        log_progress("Step 5/6: Reconstructing Mail Chains (conversation threads) & calendar meetings...", 86)
        self.build_mail_chains()
        self.process_calendar_meetings()

        log_progress("Step 6/6: Generating forensic CSV reports, Audit Summary & Standalone Outlook UI Viewer...", 95)
        self.generate_outputs()

        log_progress("Outlook Forensic extraction and Mail Chain reconstruction completed!", 100)
        return True

    def decode_chromium_ldb_bytes(self, raw_bytes):
        """
        Decodes Chromium LocalStorage / SessionStorage / LevelDB key or value bytes.
        Chromium prefixes Latin1/UTF-8 strings with 0x01 and UTF-16LE strings with 0x00.
        """
        if raw_bytes is None:
            return ""
        if isinstance(raw_bytes, str):
            return raw_bytes
        b = bytes(raw_bytes)
        if not b:
            return ""
        # Check for Chromium LocalStorage key format: _https://domain\x00\x01keyName
        if b.startswith(b"_http") and b"\x00" in b:
            parts = b.split(b"\x00", 1)
            origin = parts[0].decode("utf-8", errors="replace")
            rest = parts[1]
            if rest.startswith(b"\x01"):
                kname = rest[1:].decode("utf-8", errors="replace")
            elif rest.startswith(b"\x00"):
                kname = rest[1:].decode("utf-16-le", errors="replace")
            else:
                kname = safe_decode_bytes(rest)
            return f"{origin} :: {kname}"
        if len(b) > 1 and b[0] == 1 and b[1] in (34, 91, 123, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 116, 102) or (len(b) > 1 and b[0] == 1 and all(32 <= c < 127 or c in (9, 10, 13) for c in b[1:min(len(b), 32)])):
            return b[1:].decode("utf-8", errors="replace")
        if len(b) > 2 and b[0] == 0 and len(b[1:]) % 2 == 0:
            try:
                return b[1:].decode("utf-16-le")
            except Exception:
                pass
        return safe_decode_bytes(b)

    def ingest_record(self, db, store, ukey, val, source_file="LevelDB"):
        if hasattr(val, "value"):
            val = val.value
        val = sanitize_idb_value(val)
        if isinstance(val, str):
            s_strip = val.strip()
            if (s_strip.startswith("{") and s_strip.endswith("}")) or (s_strip.startswith("[") and s_strip.endswith("]")):
                try:
                    val = json.loads(s_strip)
                except Exception:
                    pass
        if isinstance(val, list):
            for item in val:
                if isinstance(item, dict):
                    self.ingest_record(db, store, ukey, item, source_file=source_file)
            return
        if not isinstance(val, dict):
            return

        # Unwrap nested value wrapper if present (e.g. {"key": ..., "value": {...}})
        root = val
        if "value" in root and isinstance(root["value"], dict) and len(root) <= 5 and not any(k in root for k in ("Subject", "subject", "From", "from", "Body", "body")):
            root = root["value"]
        if "data" in root and isinstance(root["data"], dict) and len(root) <= 4 and not any(k in root for k in ("Subject", "subject", "From", "from", "Body", "body")):
            root = root["data"]
        if "item" in root and isinstance(root["item"], dict) and len(root) <= 4 and not any(k in root for k in ("Subject", "subject", "From", "from", "Body", "body")):
            root = root["item"]

        if not isinstance(root, dict) or not root:
            return

        item_class = str(root.get("ItemClass") or root.get("itemClass") or root.get("MessageClass") or root.get("messageClass") or root.get("@odata.type") or "").strip()
        ic_lower = item_class.lower()

        # 1. Folder Metadata Record
        folder_id = root.get("FolderId") or root.get("folderId")
        if isinstance(folder_id, dict):
            folder_id = folder_id.get("Id") or folder_id.get("id")
        disp_name = root.get("DisplayName") or root.get("displayName")
        if (
            (folder_id and disp_name and not any(k in root for k in ("Subject", "subject", "From", "from", "Body", "body", "EmailAddress", "emailAddresses")))
            or ("folderclass" in {k.lower() for k in root.keys()})
            or ("distinguishedfolderid" in {k.lower() for k in root.keys()})
            or (ic_lower.startswith("ipf."))
        ):
            fid = str(folder_id or root.get("id") or root.get("Id") or ukey or disp_name).strip('"')
            fname = str(disp_name or root.get("FolderName") or root.get("name") or fid).strip()
            parent_fid = root.get("ParentFolderId") or root.get("parentFolderId") or ""
            if isinstance(parent_fid, dict):
                parent_fid = parent_fid.get("Id") or parent_fid.get("id") or ""
            self.folders_map[fid] = {
                "id": fid,
                "name": fname,
                "parent_id": str(parent_fid),
                "total_count": int(root.get("TotalCount") or root.get("totalItemCount") or root.get("totalCount") or 0),
                "unread_count": int(root.get("UnreadCount") or root.get("unreadItemCount") or root.get("unreadCount") or 0),
                "folder_class": str(root.get("FolderClass") or root.get("folderClass") or item_class or "IPF.Note")
            }
            return

        # 2. Calendar / Meeting / Appointment Record
        has_start = any(k in root for k in ("Start", "start", "StartTime", "startTime", "StartDate", "startDate"))
        has_end = any(k in root for k in ("End", "end", "EndTime", "endTime", "EndDate", "endDate"))
        if (
            ic_lower.startswith("ipm.appointment")
            or ic_lower.startswith("ipm.schedule.meeting")
            or "event" in ic_lower
            or (has_start and has_end and any(k in root for k in ("Subject", "subject", "Organizer", "organizer", "OrganizerName", "organizerName", "Location", "location", "IsAllDayEvent", "isAllDay")))
        ):
            rec_copy = dict(root)
            rec_copy["_source_file"] = source_file
            self.calendar_raw.append(rec_copy)
            # If it's a meeting request message (IPM.Schedule.Meeting.Request) that also has From/To/Body, also include in messages
            if not (ic_lower.startswith("ipm.schedule.meeting") and any(k in root for k in ("From", "from", "Sender", "sender", "ToRecipients", "toRecipients"))):
                return

        # 3. Contacts / People / Persona Directory Record
        if (
            ic_lower.startswith("ipm.contact")
            or ic_lower.startswith("ipm.distlist")
            or "persona" in ic_lower
            or "contact" in ic_lower
            or bool(root.get("PersonaId") or root.get("personaId") or root.get("mri"))
            or (
                bool(root.get("DisplayName") or root.get("displayName") or root.get("GivenName") or root.get("givenName"))
                and any(k in root for k in ("EmailAddress", "emailAddress", "EmailAddresses", "emailAddresses", "userPrincipalName", "UserPrincipalName", "JobTitle", "jobTitle", "CompanyName", "companyName", "Department", "department", "ImAddress", "imAddress", "Phones", "phones", "BusinessPhone", "MobilePhone"))
                and not any(k in root for k in ("Subject", "subject", "ConversationTopic", "conversationTopic", "Body", "body", "ToRecipients", "toRecipients"))
            )
        ):
            rec_copy = dict(root)
            rec_copy["_source_file"] = source_file
            self.contacts_raw.append(rec_copy)
            return

        # 4. Conversation / Thread Summary Metadata Record (OWA Conversation store)
        conv_id_val = root.get("ConversationId") or root.get("conversationId")
        if isinstance(conv_id_val, dict):
            conv_id_val = conv_id_val.get("Id") or conv_id_val.get("id")
        if (
            conv_id_val
            and any(k in root for k in ("GlobalItemIds", "globalItemIds", "ItemIds", "itemIds", "UniqueSenders", "uniqueSenders", "LastDeliveryTime", "lastDeliveryTime", "GlobalMessageCount", "MessageCount"))
            and not any(k in root for k in ("Body", "body", "NormalizedBody", "normalizedBody", "UniqueBody", "uniqueBody", "From", "from", "Sender", "sender"))
            and not isinstance(root.get("messageMap"), dict)
        ):
            cid_str = str(conv_id_val).strip('"')
            self.conv_meta_raw[cid_str] = root
            return

        # 5. Replychain / MessageMap wrapper
        if conv_id_val and isinstance(root.get("messageMap"), dict):
            for mkey, mval in root["messageMap"].items():
                if isinstance(mval, dict):
                    mcopy = dict(mval)
                    mcopy.setdefault("ConversationId", conv_id_val)
                    mcopy.setdefault("Id", mkey)
                    self.ingest_record(db, store, mkey, mcopy, source_file=source_file)
            return

        # 6. Email Message Record
        has_msg_signals = (
            ic_lower.startswith("ipm.note")
            or ic_lower.startswith("ipm.post")
            or ic_lower.startswith("report.ipm.note")
            or ic_lower.startswith("ipm.schedule.meeting")
            or "message" in ic_lower
            or any(k in root for k in (
                "InternetMessageId", "internetMessageId", "MessageId", "messageId", "Message-ID",
                "ToRecipients", "toRecipients", "CcRecipients", "ccRecipients", "DisplayTo", "displayTo",
                "DateTimeReceived", "dateTimeReceived", "ReceivedDateTime", "receivedDateTime",
                "DateTimeSent", "dateTimeSent", "SentDateTime", "sentDateTime",
                "NormalizedBody", "normalizedBody", "UniqueBody", "uniqueBody", "BodyPreview", "bodyPreview",
                "InReplyTo", "inReplyTo", "In-Reply-To", "ConversationIndex", "conversationIndex",
                "TransportHeaders", "transportHeaders", "InternetMessageHeaders", "internetMessageHeaders"
            ))
            or (
                any(k in root for k in ("Subject", "subject", "ConversationTopic", "conversationTopic"))
                and any(k in root for k in ("From", "from", "Sender", "sender", "Body", "body", "Preview", "preview", "content", "Content", "sender_name", "sender_email", "body_html", "body_plain"))
            )
            or (
                conv_id_val and any(k in root for k in ("content", "Content", "Body", "body", "imDisplayName", "From", "from"))
            )
        )
        if has_msg_signals:
            rec_copy = dict(root)
            rec_copy["_db_id"] = db
            rec_copy["_store_id"] = store
            rec_copy["_ukey"] = ukey
            rec_copy["_source_file"] = source_file
            self.messages_raw.append(rec_copy)
            return

        # 7. Check if dict is a container holding lists/dicts of messages, conversations, contacts, folders, or calendar items
        container_keys = ("messages", "Messages", "items", "Items", "mailItems", "conversations", "Conversations", "folders", "Folders", "contacts", "Contacts", "calendar", "Calendar", "events", "Events", "records", "value")
        if any(k in root for k in container_keys):
            for ck in container_keys:
                sub = root.get(ck)
                if isinstance(sub, list):
                    for item in sub:
                        if isinstance(item, dict):
                            self.ingest_record(db, store, ukey, item, source_file=source_file)
                elif isinstance(sub, dict):
                    for sub_k, sub_v in sub.items():
                        if isinstance(sub_v, dict):
                            self.ingest_record(db, store, sub_k, sub_v, source_file=source_file)

    def ingest_olk_settings_and_logs(self, search_root):
        """Parses New Outlook (Olk) UserSettings.json, xpdApi.log, and olk_*.log files."""
        candidate_files = []
        if os.path.isfile(search_root):
            candidate_files.append(search_root)
        elif os.path.isdir(search_root):
            for r, dirs, files in os.walk(search_root):
                dirs[:] = [d for d in dirs if d.lower() not in ("cache", "code cache", "gpucache", "shadercache", "grshadercache", "cases")]
                for f in files:
                    fl = f.lower()
                    if fl == "usersettings.json" or fl == "xpdapi.log" or (fl.startswith("olk_") and fl.endswith(".log")):
                        candidate_files.append(os.path.join(r, f))

        for fp in candidate_files:
            fl = os.path.basename(fp).lower()
            try:
                if fl == "usersettings.json":
                    with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                        data = json.load(f)
                    identities = data.get("Identities", {}) if isinstance(data, dict) else {}
                    id_map = identities.get("IdentityMap", {}) if isinstance(identities, dict) else {}
                    for email_addr, guid_or_hex in id_map.items():
                        self.account_identities.append({"email": email_addr, "identity_id": guid_or_hex, "source": fp})
                        if not self.primary_email or "@" in email_addr:
                            if not self.primary_email or (not self.primary_email.endswith("gmail.com") and "@" in email_addr):
                                self.primary_email = email_addr
                                user_part = email_addr.split("@")[0]
                                self.primary_user = " ".join(p.capitalize() for p in re.split(r'[._\-]+', user_part) if p)
                                domain_part = email_addr.split("@")[-1].split(".")[0].upper()
                                if domain_part:
                                    self.primary_tenant = domain_part
                        # Also add to contacts directory
                        self.contacts_raw.append({
                            "DisplayName": " ".join(p.capitalize() for p in re.split(r'[._\-]+', email_addr.split("@")[0]) if p),
                            "EmailAddress": email_addr,
                            "PersonaId": guid_or_hex,
                            "JobTitle": "Configured Outlook Mailbox Identity",
                            "CompanyName": email_addr.split("@")[-1],
                            "_source_file": os.path.basename(fp)
                        })
                    self.leveldb_records.append({
                        "source_file": os.path.basename(fp),
                        "table_name": "Olk UserSettings",
                        "seq": 0,
                        "record_type": "JSON Config",
                        "key": "Identities.IdentityMap",
                        "value": json.dumps(id_map, ensure_ascii=False),
                        "timestamp": str(data.get("UpdateSettings", {}).get("BootAfterUpdateTime") or "")
                    })
                    self.leveldb_records.append({
                        "source_file": os.path.basename(fp),
                        "table_name": "Olk UserSettings",
                        "seq": 1,
                        "record_type": "JSON Config",
                        "key": "UserSettings.Full",
                        "value": json.dumps(data, ensure_ascii=False)[:2000],
                        "timestamp": str(data.get("UpdateSettings", {}).get("BootAfterUpdateTime") or "")
                    })
                elif fl == "xpdapi.log":
                    with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                        lines = [ln.strip() for ln in f if ln.strip()]
                    pkg_names = set()
                    client_ids = set()
                    first_ts, last_ts = "", ""
                    for ln in lines:
                        try:
                            obj = json.loads(ln)
                            ts = obj.get("Timestamp") or ""
                            if ts and not first_ts:
                                first_ts = ts
                            if ts:
                                last_ts = ts
                            if obj.get("CurrentPackageFullName"):
                                pkg_names.add(obj["CurrentPackageFullName"])
                            if obj.get("SusClientId"):
                                client_ids.add(obj["SusClientId"])
                        except Exception:
                            continue
                    self.leveldb_records.append({
                        "source_file": os.path.basename(fp),
                        "table_name": "Olk XPD Package Log",
                        "seq": len(lines),
                        "record_type": "Telemetry JSONL",
                        "key": "PackageDeploymentSummary",
                        "value": json.dumps({
                            "total_events": len(lines),
                            "packages": sorted(pkg_names),
                            "client_ids": sorted(client_ids),
                            "first_timestamp": first_ts,
                            "last_timestamp": last_ts
                        }, ensure_ascii=False),
                        "timestamp": last_ts
                    })
                elif fl.startswith("olk_") and fl.endswith(".log"):
                    with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                        lines = [ln.strip() for ln in f if ln.strip()]
                    session_id, device_id, cmd_line, boot_time = "", "", "", ""
                    for ln in lines[:40]:
                        if "sessionId\t" in ln:
                            parts = ln.split("\t")
                            if len(parts) > 1:
                                boot_time = parts[1]
                            for idx, tok in enumerate(parts):
                                if tok == "sessionId" and idx + 1 < len(parts):
                                    session_id = parts[idx + 1]
                                if tok == "deviceId" and idx + 1 < len(parts):
                                    device_id = parts[idx + 1]
                        if "Command-line\t" in ln or "commandLineArguments\t" in ln:
                            cmd_line = ln.split("\t")[-1]
                    self.leveldb_records.append({
                        "source_file": os.path.basename(fp),
                        "table_name": "Olk Host Session Log",
                        "seq": len(lines),
                        "record_type": "Host Trace",
                        "key": f"Session_{session_id or os.path.basename(fp)}",
                        "value": json.dumps({
                            "sessionId": session_id,
                            "deviceId": device_id,
                            "bootTime": boot_time,
                            "commandLine": cmd_line,
                            "eventCount": len(lines)
                        }, ensure_ascii=False),
                        "timestamp": boot_time
                    })
            except Exception as e:
                log_progress(f"  Notice reading Olk metadata file {os.path.basename(fp)}: {e}")

    def ingest_leveldb_files(self, leveldb_dirs, standalone_files):
        ChromiumRecord, LevelDBRecord, LevelDBFolderReader = init_native_indexeddb_engine()

        all_ldb_files = []
        for d in leveldb_dirs:
            try:
                for f in sorted(os.listdir(d)):
                    if f.lower().endswith((".ldb", ".log")):
                        all_ldb_files.append((os.path.basename(d), os.path.join(d, f)))
            except Exception:
                pass
        for fp in standalone_files:
            all_ldb_files.append((os.path.basename(os.path.dirname(fp)) or "LevelDB", fp))

        seen_fps = set()
        unique_ldb_files = []
        for tbl_name, fp in all_ldb_files:
            norm_fp = os.path.normpath(fp)
            if norm_fp not in seen_fps:
                seen_fps.add(norm_fp)
                unique_ldb_files.append((tbl_name, norm_fp))

        if not unique_ldb_files:
            return

        log_progress(f"  Parsing {len(unique_ldb_files)} LevelDB (.ldb / .log) files via Native Forensic Engine...")

        for tbl_name, fp in unique_ldb_files:
            fname = os.path.basename(fp)
            self.source_files_ingested.append(fp)
            idb_parsed_count = 0

            # 1. Try Chromium IndexedDB Decoder (for *.indexeddb.leveldb tables)
            if ChromiumRecord is not None:
                try:
                    for rec in ChromiumRecord.FromFile(pathlib.Path(fp)):
                        db_id = getattr(rec, "database_id", None) or (rec.get("database_id") if isinstance(rec, dict) else None)
                        store_id = getattr(rec, "object_store_id", None) or (rec.get("object_store_id") if isinstance(rec, dict) else None)
                        val = getattr(rec, "value", None) or (rec.get("value") if isinstance(rec, dict) else None)
                        key_obj = getattr(rec, "key", None) or (rec.get("key") if isinstance(rec, dict) else None)
                        seq_no = getattr(rec, "sequence_number", 0)
                        ukey = None
                        if key_obj:
                            enc = getattr(key_obj, "encoded_user_key", None) or (key_obj.get("encoded_user_key") if isinstance(key_obj, dict) else None)
                            if enc:
                                ukey_val = getattr(enc, "value", None) or (enc.get("value") if isinstance(enc, dict) else None)
                                if ukey_val is not None:
                                    try:
                                        ukey = json.dumps(sanitize_idb_value(ukey_val))
                                    except Exception:
                                        ukey = str(ukey_val)
                        if val is not None:
                            idb_parsed_count += 1
                            self.ingest_record(db_id, store_id, ukey, val, source_file=f"{tbl_name}/{fname}")
                            if len(self.leveldb_records) < 2500:
                                san_v = sanitize_idb_value(val)
                                try:
                                    v_str = json.dumps(san_v, ensure_ascii=False)[:1500]
                                except Exception:
                                    v_str = str(san_v)[:1500]
                                self.leveldb_records.append({
                                    "source_file": f"{tbl_name}/{fname}",
                                    "table_name": f"IndexedDB (DB:{db_id} Store:{store_id})",
                                    "seq": seq_no or idb_parsed_count,
                                    "record_type": "IndexedDB Record",
                                    "key": str(ukey or ""),
                                    "value": v_str,
                                    "timestamp": ""
                                })
                except Exception:
                    pass

            # 2. Also run Raw LevelDB Record Reader (for Local Storage, Session Storage, Sync Data, or raw JSON-in-LevelDB tables)
            raw_ldb_count = 0
            if LevelDBRecord is not None:
                try:
                    for rec_wrapper in LevelDBRecord.FromFile(pathlib.Path(fp)):
                        inner = getattr(rec_wrapper, "record", rec_wrapper)
                        raw_k = getattr(inner, "key", b"")
                        raw_v = getattr(inner, "value", b"")
                        seq_no = getattr(inner, "sequence_number", 0)
                        rtype = getattr(inner, "record_type", "Value")

                        # Skip if this file was already decoded as pure binary IndexedDB records unless key/value is readable text/JSON
                        k_str = self.decode_chromium_ldb_bytes(raw_k)
                        v_str = self.decode_chromium_ldb_bytes(raw_v)
                        raw_ldb_count += 1

                        # Extract timestamp if embedded in JSON value
                        ts_extracted = ""
                        v_strip = v_str.strip()
                        if (v_strip.startswith("{") and v_strip.endswith("}")) or (v_strip.startswith("[") and v_strip.endswith("]")):
                            try:
                                parsed_json = json.loads(v_strip)
                                if isinstance(parsed_json, dict):
                                    for tk in ("lastClientActiveDate", "lastImportDate", "DateTimeReceived", "receivedDateTime", "Timestamp", "timestamp", "startTime", "Date"):
                                        if parsed_json.get(tk):
                                            ts_extracted = str(parsed_json[tk])
                                            break
                                # Also pass to ingest_record in case raw LevelDB stores mail/contact/calendar JSON
                                self.ingest_record(tbl_name, fname, k_str, parsed_json, source_file=f"{tbl_name}/{fname}")
                            except Exception:
                                pass

                        if len(self.leveldb_records) < 2500:
                            # Clean printable check for key
                            clean_k = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', ' ', k_str).strip()
                            clean_v = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', ' ', v_str).strip()
                            if clean_k or clean_v:
                                self.leveldb_records.append({
                                    "source_file": f"{tbl_name}/{fname}",
                                    "table_name": tbl_name,
                                    "seq": int(seq_no or raw_ldb_count),
                                    "record_type": str(rtype).split(".")[-1],
                                    "key": clean_k[:300],
                                    "value": clean_v[:2000],
                                    "timestamp": ts_extracted
                                })
                except Exception:
                    pass

            # 3. Fallback Carve: If neither ChromiumIndexedDBRecord nor LevelDBRecord yielded records (e.g. raw/carved .ldb/.log fragment), scan for JSON objects
            if idb_parsed_count == 0 and raw_ldb_count == 0:
                self.carve_json_objects_from_file(fp, source_label=f"{tbl_name}/{fname}")

    def carve_json_objects_from_file(self, fp, source_label=""):
        """Scans binary or text file for embedded JSON objects representing Outlook artifacts."""
        try:
            with open(fp, "rb") as f:
                raw_data = f.read(32 * 1024 * 1024)
            text = safe_decode_bytes(raw_data)
            # Look for JSON objects containing key Outlook markers
            for m in re.finditer(r'\{[^{}]*(?:"Subject"|"subject"|"ConversationId"|"conversationId"|"From"|"from"|"ToRecipients"|"toRecipients"|"InternetMessageId"|"EmailAddress")[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', text):
                cand = m.group(0)
                try:
                    obj = json.loads(cand)
                    if isinstance(obj, dict):
                        self.ingest_record("Carved", source_label, None, obj, source_file=source_label or os.path.basename(fp))
                except Exception:
                    continue
        except Exception:
            pass

    def extract_pff_mapi_props(self, pff_item):
        """
        Extracts all MAPI properties from a pypff item (message, attachment, recipient, folder).
        Returns (props_by_tag_int, named_props_dict).
        """
        MAPI_TAG_NAMES = {
            0x0017: "PR_IMPORTANCE",
            0x001A: "PR_MESSAGE_CLASS",
            0x0036: "PR_SENSITIVITY",
            0x0037: "PR_SUBJECT",
            0x0039: "PR_CLIENT_SUBMIT_TIME",
            0x003D: "PR_SUBJECT_PREFIX",
            0x0040: "PR_RECEIVED_BY_NAME",
            0x0042: "PR_SENT_REPRESENTING_NAME",
            0x0060: "PR_START_DATE",
            0x0061: "PR_END_DATE",
            0x0064: "PR_SENT_REPRESENTING_ADDRTYPE",
            0x0065: "PR_SENT_REPRESENTING_EMAIL_ADDRESS",
            0x0070: "PR_CONVERSATION_TOPIC",
            0x0071: "PR_CONVERSATION_INDEX",
            0x0075: "PR_RECEIVED_BY_ADDRTYPE",
            0x0076: "PR_RECEIVED_BY_EMAIL_ADDRESS",
            0x007D: "PR_TRANSPORT_MESSAGE_HEADERS",
            0x0C15: "PR_RECIPIENT_TYPE",
            0x0C1A: "PR_SENDER_NAME",
            0x0C1E: "PR_SENDER_ADDRTYPE",
            0x0C1F: "PR_SENDER_EMAIL_ADDRESS",
            0x0E02: "PR_DISPLAY_BCC",
            0x0E03: "PR_DISPLAY_CC",
            0x0E04: "PR_DISPLAY_TO",
            0x0E06: "PR_MESSAGE_DELIVERY_TIME",
            0x0E07: "PR_MESSAGE_FLAGS",
            0x0E08: "PR_MESSAGE_SIZE",
            0x1000: "PR_BODY",
            0x1009: "PR_RTF_COMPRESSED",
            0x1013: "PR_HTML",
            0x1035: "PR_INTERNET_MESSAGE_ID",
            0x1039: "PR_INTERNET_REFERENCES",
            0x1042: "PR_IN_REPLY_TO_ID",
            0x3001: "PR_DISPLAY_NAME",
            0x3002: "PR_ADDRTYPE",
            0x3003: "PR_EMAIL_ADDRESS",
            0x3007: "PR_CREATION_TIME",
            0x3008: "PR_LAST_MODIFICATION_TIME",
            0x3013: "PR_CONVERSATION_ID",
            0x3701: "PR_ATTACH_DATA_BINARY",
            0x3703: "PR_ATTACH_EXTENSION",
            0x3704: "PR_ATTACH_FILENAME",
            0x3705: "PR_ATTACH_METHOD",
            0x3707: "PR_ATTACH_LONG_FILENAME",
            0x370E: "PR_ATTACH_MIME_TAG",
            0x3712: "PR_ATTACH_CONTENT_ID",
            0x3713: "PR_ATTACH_CONTENT_LOCATION",
            0x3714: "PR_ATTACH_FLAGS",
            0x39FE: "PR_SMTP_ADDRESS",
            0x3A06: "PR_GIVEN_NAME",
            0x3A08: "PR_BUSINESS_TELEPHONE_NUMBER",
            0x3A11: "PR_SURNAME",
            0x3A16: "PR_COMPANY_NAME",
            0x3A17: "PR_TITLE",
            0x3A18: "PR_DEPARTMENT_NAME",
            0x3A19: "PR_OFFICE_LOCATION",
            0x3A1C: "PR_MOBILE_TELEPHONE_NUMBER",
            0x5D01: "PR_SENDER_SMTP_ADDRESS",
            0x5D02: "PR_SENT_REPRESENTING_SMTP_ADDRESS",
            0x5D07: "PR_RECEIVED_BY_SMTP_ADDRESS",
            0x8208: "PR_APPOINTMENT_LOCATION",
            0x820D: "PR_APPOINTMENT_START_WHOLE",
            0x820E: "PR_APPOINTMENT_END_WHOLE",
        }
        props_by_tag = {}
        named_props = {}
        try:
            num_sets = getattr(pff_item, "number_of_record_sets", 0) or 0
            for s_idx in range(num_sets):
                rset = pff_item.get_record_set(s_idx)
                num_entries = getattr(rset, "number_of_entries", 0) or 0
                for e_idx in range(num_entries):
                    entry = rset.get_entry(e_idx)
                    etag = getattr(entry, "entry_type", None)
                    vtype = getattr(entry, "value_type", None)
                    if etag is None:
                        continue
                    val = None
                    # String types: 0x001e (ASCII), 0x001f (UTF-16)
                    if vtype in (0x001E, 0x001F):
                        try:
                            val = entry.data_as_string
                        except Exception:
                            try:
                                val = safe_decode_bytes(entry.data)
                            except Exception:
                                val = None
                    # Integer types: 0x0002 (int16), 0x0003 (int32), 0x0014 (int64)
                    elif vtype in (0x0002, 0x0003, 0x0014):
                        try:
                            val = entry.data_as_integer
                        except Exception:
                            val = None
                    # Boolean: 0x000B
                    elif vtype == 0x000B:
                        try:
                            val = entry.data_as_boolean
                        except Exception:
                            val = None
                    # Systime / Datetime: 0x0040
                    elif vtype == 0x0040:
                        try:
                            val = entry.data_as_datetime
                        except Exception:
                            try:
                                val = entry.data_as_integer
                            except Exception:
                                val = None
                    # Binary: 0x0102
                    elif vtype == 0x0102:
                        try:
                            val = entry.data
                        except Exception:
                            val = None
                    else:
                        for attr in ("data_as_string", "data_as_integer", "data_as_datetime", "data_as_boolean", "data"):
                            try:
                                cand = getattr(entry, attr)
                                if cand is not None:
                                    val = cand
                                    break
                            except Exception:
                                continue

                    if val is not None:
                        props_by_tag[etag] = val
                        tname = MAPI_TAG_NAMES.get(etag, f"0x{etag:04X}")
                        if etag == 0x3701:
                            named_props[tname] = f"<Binary {len(val) if isinstance(val, (bytes, bytearray)) else 0} bytes>"
                        elif isinstance(val, (bytes, bytearray, memoryview)):
                            if etag in (0x1013, 0x1000, 0x007D):
                                named_props[tname] = safe_decode_bytes(val)[:500]
                            else:
                                named_props[tname] = bytes(val).hex()
                        elif isinstance(val, datetime.datetime):
                            u_t, _, _ = format_time(val)
                            named_props[tname] = u_t
                        else:
                            named_props[tname] = val
        except Exception:
            pass
        return props_by_tag, named_props

    def parse_pff_message(self, pff_msg, folder_path, source_file, is_orphan=False):
        """Extracts a complete message, calendar event, or contact from a pypff.message object."""
        props_by_tag, named_props = self.extract_pff_mapi_props(pff_msg)

        def safe_attr(obj, attr_name, fallback_tags=()):
            try:
                v = getattr(obj, attr_name, None)
                if callable(v):
                    v = v()
                if v is not None and v != "":
                    return v
            except Exception:
                pass
            for t in fallback_tags:
                if t in props_by_tag and props_by_tag[t] is not None:
                    return props_by_tag[t]
            return None

        msg_class = str(props_by_tag.get(0x001A) or "IPM.Note").strip()
        mc_lower = msg_class.lower()

        subject = safe_decode_bytes(safe_attr(pff_msg, "subject", (0x0037,)))
        conv_topic = safe_decode_bytes(safe_attr(pff_msg, "conversation_topic", (0x0070,))) or subject
        conv_index_raw = safe_attr(pff_msg, "conversation_index", (0x0071,))
        transport_headers_raw = safe_decode_bytes(safe_attr(pff_msg, "transport_headers", (0x007D,)))

        # Parse RFC 5322 headers if transport_headers are present
        parsed_headers = {}
        if transport_headers_raw and ":" in transport_headers_raw:
            try:
                emsg = email.message_from_string(transport_headers_raw)
                for hk, hv in emsg.items():
                    decoded_hv = decode_mime_words(hv)
                    if hk in parsed_headers:
                        parsed_headers[hk] += "; " + decoded_hv
                    else:
                        parsed_headers[hk] = decoded_hv
            except Exception:
                pass

        sender_name = safe_decode_bytes(safe_attr(pff_msg, "sender_name", (0x0C1A, 0x0042)))
        sender_email = safe_decode_bytes(
            props_by_tag.get(0x5D01)
            or props_by_tag.get(0x5D02)
            or props_by_tag.get(0x39FE)
            or props_by_tag.get(0x0C1F)
            or props_by_tag.get(0x0065)
            or ""
        )
        if parsed_headers.get("From"):
            from_list = parse_email_address_list(parsed_headers["From"])
            if from_list:
                if not sender_name or sender_name == sender_email:
                    sender_name = from_list[0]["name"]
                if not sender_email or "/o=" in sender_email.lower():
                    if from_list[0]["email"]:
                        sender_email = from_list[0]["email"]

        # Extract recipients from pff_msg.recipients table + MAPI display properties + headers
        to_list, cc_list, bcc_list = [], [], []
        try:
            recips_obj = getattr(pff_msg, "recipients", None)
            if recips_obj:
                num_r_sets = getattr(recips_obj, "number_of_record_sets", 0) or 0
                for r_idx in range(num_r_sets):
                    rset = recips_obj.get_record_set(r_idx)
                    r_props = {}
                    for e_idx in range(getattr(rset, "number_of_entries", 0) or 0):
                        ent = rset.get_entry(e_idx)
                        et = getattr(ent, "entry_type", None)
                        try:
                            if et in (0x3001, 0x3003, 0x39FE, 0x5D01):
                                r_props[et] = ent.data_as_string
                            elif et == 0x0C15:
                                r_props[et] = ent.data_as_integer
                        except Exception:
                            continue
                    r_name = r_props.get(0x3001) or ""
                    r_email = r_props.get(0x39FE) or r_props.get(0x5D01) or r_props.get(0x3003) or ""
                    r_type = r_props.get(0x0C15, 1)
                    parsed_r = parse_email_address_list({"name": r_name, "address": r_email})
                    if r_type == 2:
                        cc_list.extend(parsed_r)
                    elif r_type == 3:
                        bcc_list.extend(parsed_r)
                    else:
                        to_list.extend(parsed_r)
        except Exception:
            pass

        if not to_list:
            to_raw = safe_decode_bytes(props_by_tag.get(0x0E04) or parsed_headers.get("To") or props_by_tag.get(0x5D07) or props_by_tag.get(0x0076) or "")
            to_list = parse_email_address_list(to_raw)
        if not cc_list:
            cc_raw = safe_decode_bytes(props_by_tag.get(0x0E03) or parsed_headers.get("Cc") or parsed_headers.get("CC") or "")
            cc_list = parse_email_address_list(cc_raw)
        if not bcc_list:
            bcc_raw = safe_decode_bytes(props_by_tag.get(0x0E02) or parsed_headers.get("Bcc") or parsed_headers.get("BCC") or "")
            bcc_list = parse_email_address_list(bcc_raw)

        # Bodies: HTML, Plain Text, RTF (with LZFU decompression & RTFDE de-encapsulation)
        html_body = safe_decode_bytes(safe_attr(pff_msg, "html_body", (0x1013,))).rstrip("\x00")
        plain_body = safe_decode_bytes(safe_attr(pff_msg, "plain_text_body", (0x1000,))).rstrip("\x00")
        rtf_body_raw = safe_attr(pff_msg, "rtf_body", (0x1009,))
        rtf_text = ""
        if rtf_body_raw:
            rtf_text, rtf_html, rtf_plain = decode_rtf_body(rtf_body_raw)
            if not html_body and rtf_html:
                html_body = rtf_html
            if not plain_body and rtf_plain:
                plain_body = rtf_plain

        # Timestamps
        delivery_time = safe_attr(pff_msg, "delivery_time", (0x0E06,))
        submit_time = safe_attr(pff_msg, "client_submit_time", (0x0039,))
        creation_time = safe_attr(pff_msg, "creation_time", (0x3007,))
        mod_time = safe_attr(pff_msg, "modification_time", (0x3008,))
        primary_time = delivery_time or submit_time or creation_time or mod_time or parsed_headers.get("Date")

        msg_identifier = safe_attr(pff_msg, "identifier", ()) or len(self.messages_raw) + 1
        internet_msg_id = safe_decode_bytes(props_by_tag.get(0x1035) or parsed_headers.get("Message-ID") or parsed_headers.get("Message-Id") or "")
        in_reply_to = safe_decode_bytes(props_by_tag.get(0x1042) or parsed_headers.get("In-Reply-To") or "")
        references = safe_decode_bytes(props_by_tag.get(0x1039) or parsed_headers.get("References") or "")
        conv_id = safe_decode_bytes(props_by_tag.get(0x3013) or parsed_headers.get("Thread-Index") or "")

        # Message Flags: 0x0001 = MSGFLAG_READ, 0x0008 = MSGFLAG_UNSENT (Draft)
        msg_flags = props_by_tag.get(0x0E07)
        is_read = bool(msg_flags & 0x01) if isinstance(msg_flags, int) else True
        is_draft = bool(msg_flags & 0x08) if isinstance(msg_flags, int) else ("draft" in folder_path.lower())
        importance_code = props_by_tag.get(0x0017)
        importance = {2: "High", 0: "Low"}.get(importance_code, "Normal")
        sensitivity_code = props_by_tag.get(0x0036)
        sensitivity = {1: "Personal", 2: "Private", 3: "Confidential"}.get(sensitivity_code, "Normal")

        # Handle Calendar Items in PST/OST
        if mc_lower.startswith("ipm.appointment") or ("calendar" in folder_path.lower() and not mc_lower.startswith("ipm.note")):
            appt_start = props_by_tag.get(0x820D) or props_by_tag.get(0x0060) or primary_time
            appt_end = props_by_tag.get(0x820E) or props_by_tag.get(0x0061) or appt_start
            appt_loc = safe_decode_bytes(props_by_tag.get(0x8208) or "")
            self.calendar_raw.append({
                "Subject": subject or conv_topic or "Calendar Appointment",
                "OrganizerName": sender_name,
                "OrganizerAddress": sender_email,
                "Attendees": [r["display"] for r in (to_list + cc_list)],
                "StartTime": appt_start,
                "EndTime": appt_end,
                "Location": appt_loc,
                "Body": plain_body or html_to_plain_text(html_body),
                "_source_file": source_file
            })
            if not mc_lower.startswith("ipm.schedule.meeting"):
                return

        # Handle Contact Items in PST/OST
        if mc_lower.startswith("ipm.contact") or ("contact" in folder_path.lower() and not mc_lower.startswith("ipm.note")):
            c_name = safe_decode_bytes(props_by_tag.get(0x3001) or subject or f"{props_by_tag.get(0x3A06, '')} {props_by_tag.get(0x3A11, '')}".strip())
            c_email = safe_decode_bytes(props_by_tag.get(0x8083) or props_by_tag.get(0x8093) or props_by_tag.get(0x39FE) or props_by_tag.get(0x3003) or sender_email or "")
            self.contacts_raw.append({
                "DisplayName": c_name,
                "EmailAddress": c_email,
                "GivenName": safe_decode_bytes(props_by_tag.get(0x3A06) or ""),
                "Surname": safe_decode_bytes(props_by_tag.get(0x3A11) or ""),
                "CompanyName": safe_decode_bytes(props_by_tag.get(0x3A16) or ""),
                "JobTitle": safe_decode_bytes(props_by_tag.get(0x3A17) or ""),
                "Department": safe_decode_bytes(props_by_tag.get(0x3A18) or ""),
                "BusinessPhone": safe_decode_bytes(props_by_tag.get(0x3A08) or ""),
                "MobilePhone": safe_decode_bytes(props_by_tag.get(0x3A1C) or ""),
                "_source_file": source_file
            })
            return

        # Extract Attachments from pff_msg
        extracted_atts = []
        try:
            num_atts = getattr(pff_msg, "number_of_attachments", 0) or 0
            for a_idx in range(num_atts):
                att = pff_msg.get_attachment(a_idx)
                a_props, _ = self.extract_pff_mapi_props(att)
                a_name = safe_decode_bytes(
                    a_props.get(0x3707)
                    or a_props.get(0x3704)
                    or a_props.get(0x3001)
                    or getattr(att, "long_filename", None)
                    or getattr(att, "name", None)
                    or f"attachment_{msg_identifier}_{a_idx + 1}"
                )
                a_mime = safe_decode_bytes(a_props.get(0x370E) or "")
                a_cid = safe_decode_bytes(a_props.get(0x3712) or "")
                a_size = 0
                try:
                    a_size = getattr(att, "size", 0)
                    if callable(a_size):
                        a_size = a_size()
                except Exception:
                    a_size = 0

                a_bytes = None
                try:
                    if hasattr(att, "seek_offset"):
                        att.seek_offset(0)
                    if hasattr(att, "read_buffer") and a_size and a_size > 0:
                        a_bytes = att.read_buffer(a_size)
                except Exception:
                    pass
                if not a_bytes and isinstance(a_props.get(0x3701), (bytes, bytearray, memoryview)):
                    a_bytes = bytes(a_props[0x3701])

                # Also check if this PFF attachment is an embedded Outlook message (PR_ATTACH_METHOD == 5)
                attach_method = a_props.get(0x3705)
                num_sub_items = getattr(att, "number_of_sub_items", 0) or 0
                if callable(num_sub_items):
                    try:
                        num_sub_items = num_sub_items()
                    except Exception:
                        num_sub_items = 0
                if (attach_method == 5 or num_sub_items > 0) and hasattr(att, "get_sub_item"):
                    for sub_idx in range(max(1, num_sub_items)):
                        try:
                            sub_item = att.get_sub_item(sub_idx)
                            if sub_item is not None:
                                self.parse_pff_message(sub_item, folder_path, f"{os.path.basename(source_file)}!{a_name}", is_orphan=is_orphan)
                        except Exception:
                            break

                extracted_atts.append({
                    "Name": a_name,
                    "ContentType": a_mime or ("application/vnd.ms-outlook" if attach_method == 5 else ""),
                    "ContentId": a_cid,
                    "IsInline": bool(a_cid),
                    "Size": len(a_bytes) if a_bytes else (a_size or 0),
                    "_raw_bytes": a_bytes
                })
        except Exception as e:
            log_progress(f"  Notice reading attachment on PFF message {msg_identifier}: {e}")

        conv_idx_hex = ""
        if isinstance(conv_index_raw, (bytes, bytearray, memoryview)):
            conv_idx_hex = bytes(conv_index_raw).hex()
        elif conv_index_raw:
            conv_idx_hex = str(conv_index_raw)

        self.messages_raw.append({
            "Id": f"pff_{os.path.basename(source_file)}_{msg_identifier}",
            "ItemClass": msg_class,
            "Subject": subject,
            "ConversationTopic": conv_topic,
            "ConversationId": conv_id,
            "ConversationIndex": conv_idx_hex,
            "InternetMessageId": internet_msg_id,
            "InReplyTo": in_reply_to,
            "References": references,
            "From": {"Name": sender_name, "EmailAddress": sender_email},
            "ToRecipients": to_list,
            "CcRecipients": cc_list,
            "BccRecipients": bcc_list,
            "DateTimeReceived": primary_time,
            "DateTimeSent": submit_time or primary_time,
            "DateTimeCreated": creation_time,
            "LastModifiedTime": mod_time,
            "body_html": html_body,
            "body_plain": plain_body,
            "body_rtf": rtf_text[:5000] if rtf_text else "",
            "TransportHeaders": transport_headers_raw,
            "ParsedHeaders": parsed_headers,
            "MapiProperties": named_props,
            "FolderName": "[Recovered Orphan Items]" if is_orphan else folder_path,
            "Importance": importance,
            "Sensitivity": sensitivity,
            "IsRead": is_read,
            "IsDraft": is_draft,
            "IsDeleted": is_orphan or ("deleted" in folder_path.lower()),
            "Attachments": extracted_atts,
            "_source_file": os.path.basename(source_file)
        })

    def parse_pff_file(self, file_path):
        """Parses an Outlook .pst or .ost file using pypff (with fallback carving if damaged)."""
        log_progress(f"  Opening Outlook PFF (OST/PST) file: {os.path.basename(file_path)}...")
        self.source_files_ingested.append(file_path)
        try:
            import pypff
            pff_file = pypff.file()
            pff_file.open(file_path)
        except Exception as e:
            log_progress(f"  Notice: pypff could not open {os.path.basename(file_path)} directly ({e}); attempting raw forensic carve...")
            self.carve_raw_emails_from_binary(file_path)
            return

        try:
            def walk_folder(folder, current_path=""):
                fname = getattr(folder, "name", None)
                if callable(fname):
                    fname = fname()
                fname_str = safe_decode_bytes(fname).strip() if fname else ""
                next_path = f"{current_path}/{fname_str}".strip("/") if fname_str else current_path

                # Record folder metadata
                fid = getattr(folder, "identifier", None)
                if callable(fid):
                    fid = fid()
                num_msgs = getattr(folder, "number_of_sub_messages", 0) or 0
                if fname_str and num_msgs > 0:
                    norm_fn = self.normalize_folder_name(next_path)
                    self.folders_map[str(fid or norm_fn)] = {
                        "id": str(fid or norm_fn),
                        "name": norm_fn,
                        "parent_id": "",
                        "total_count": num_msgs,
                        "unread_count": 0,
                        "folder_class": "IPF.Note"
                    }

                for m_idx in range(num_msgs):
                    try:
                        sub_msg = folder.get_sub_message(m_idx)
                        self.parse_pff_message(sub_msg, next_path or "Inbox", file_path, is_orphan=False)
                    except Exception as me:
                        log_progress(f"  Warning parsing message #{m_idx} in {next_path}: {me}")

                num_sub = getattr(folder, "number_of_sub_folders", 0) or 0
                for f_idx in range(num_sub):
                    try:
                        sub_f = folder.get_sub_folder(f_idx)
                        walk_folder(sub_f, next_path)
                    except Exception as fe:
                        log_progress(f"  Warning walking subfolder #{f_idx} in {next_path}: {fe}")

            root_folder = pff_file.get_root_folder()
            if root_folder:
                walk_folder(root_folder, "")

            # Also check orphan items (deleted/unlinked PFF nodes)
            num_orphans = getattr(pff_file, "number_of_orphan_items", 0) or 0
            for o_idx in range(num_orphans):
                try:
                    orphan = pff_file.get_orphan_item(o_idx)
                    if hasattr(orphan, "subject") or hasattr(orphan, "number_of_record_sets"):
                        self.parse_pff_message(orphan, "[Recovered Orphan Items]", file_path, is_orphan=True)
                except Exception:
                    continue

            pff_file.close()
        except Exception as e:
            log_progress(f"  Warning during PFF traversal of {os.path.basename(file_path)}: {e}")

    def carve_raw_emails_from_binary(self, file_path):
        """Fallback carver for RFC 5322 email blocks or JSON payloads inside raw/damaged OST/PST/binary files."""
        try:
            with open(file_path, "rb") as f:
                data = f.read(64 * 1024 * 1024)
            # 1. Check if it contains JSON objects
            self.carve_json_objects_from_file(file_path, source_label=os.path.basename(file_path))
            # 2. Scan for RFC 5322 headers (From: ... Subject: ... or Message-ID: ...)
            text = data.decode("latin-1", errors="ignore")
            for m in re.finditer(r'(?:^|\r?\n)((?:Received|From|Date|Subject|Message-ID|MIME-Version):\s+[^\r\n]+(?:\r?\n[A-Za-z0-9\-]+:\s+[^\r\n]+|\r?\n[ \t]+[^\r\n]+){2,}\r?\n\r?\n[\s\S]{10,20000}?)(?=\r?\n(?:From |Received: |Message-ID: )|\x00{4,}|$)', text):
                raw_eml = m.group(1).strip("\x00 \r\n")
                if "Subject:" in raw_eml or "From:" in raw_eml:
                    self.parse_eml_bytes(raw_eml.encode("latin-1", errors="ignore"), source_file=os.path.basename(file_path), folder_name="[Carved Emails]")
        except Exception as e:
            log_progress(f"  Carving fallback notice for {os.path.basename(file_path)}: {e}")

    def parse_msg_object(self, m, source_label, folder_name="Exported MSG"):
        """Extracts a message, calendar meeting, or contact from an open extract_msg.MSGFile / Message instance."""
        msg_class = safe_decode_bytes(getattr(m, "classType", None) or m.getStringStream("__substg1.0_001A") or "IPM.Note").strip()
        mc_lower = msg_class.lower()

        subj = safe_decode_bytes(getattr(m, "subject", None) or m.getStringStream("__substg1.0_0037") or "").rstrip("\x00")
        conv_topic = safe_decode_bytes(m.getStringStream("__substg1.0_0070") or "").rstrip("\x00") or normalize_subject(subj)
        conv_idx_bytes = m.getStream("__substg1.0_00710102")
        conv_idx_hex = conv_idx_bytes.hex() if isinstance(conv_idx_bytes, (bytes, bytearray)) else ""

        # Extract genuine transport headers stream (__substg1.0_007D) if present
        raw_headers_str = safe_decode_bytes(getattr(m, "headerText", None) or m.getStringStream("__substg1.0_007D") or "").rstrip("\x00")
        if raw_headers_str.startswith("Microsoft Mail Internet Headers Version 2.0"):
            raw_headers_str = raw_headers_str[43:].lstrip()
        headers_dict = {}
        if raw_headers_str and ":" in raw_headers_str:
            try:
                emsg = email.message_from_string(raw_headers_str)
                for hk, hv in emsg.items():
                    if hv is not None and str(hv).strip():
                        dec_hv = decode_mime_words(hv)
                        headers_dict[hk] = (headers_dict[hk] + "; " + dec_hv) if hk in headers_dict else dec_hv
            except Exception:
                pass

        # Extract sender and structured recipients
        sender = safe_decode_bytes(getattr(m, "sender", None) or "").rstrip("\x00")
        if not sender:
            s_name = safe_decode_bytes(m.getStringStream("__substg1.0_0C1A") or m.getStringStream("__substg1.0_0042") or "").rstrip("\x00")
            s_smtp = safe_decode_bytes(m.getStringStream("__substg1.0_5D01") or m.getStringStream("__substg1.0_5D02") or m.getStringStream("__substg1.0_0C1F") or "").rstrip("\x00")
            sender = f"{s_name} <{s_smtp}>" if (s_name and s_smtp) else (s_smtp or s_name)

        to_list, cc_list, bcc_list = [], [], []
        try:
            for r in (getattr(m, "recipients", None) or []):
                r_name = safe_decode_bytes(getattr(r, "name", "") or "").rstrip("\x00")
                r_email = safe_decode_bytes(getattr(r, "smtpAddress", None) or getattr(r, "email", "") or "").rstrip("\x00")
                r_type_val = int(getattr(r, "typeFlags", 1) or 1) & 0x0F
                parsed_r = parse_email_address_list({"name": r_name, "address": r_email})
                if r_type_val == 2:
                    cc_list.extend(parsed_r)
                elif r_type_val == 3:
                    bcc_list.extend(parsed_r)
                else:
                    to_list.extend(parsed_r)
        except Exception:
            pass

        if not to_list:
            to_list = parse_email_address_list(safe_decode_bytes(getattr(m, "to", None) or m.getStringStream("__substg1.0_0E04") or headers_dict.get("To") or ""))
        if not cc_list:
            cc_list = parse_email_address_list(safe_decode_bytes(getattr(m, "cc", None) or m.getStringStream("__substg1.0_0E03") or headers_dict.get("Cc") or ""))
        if not bcc_list:
            bcc_list = parse_email_address_list(safe_decode_bytes(getattr(m, "bcc", None) or m.getStringStream("__substg1.0_0E02") or headers_dict.get("Bcc") or ""))

        date_val = getattr(m, "date", None) or getattr(m, "receivedTime", None) or headers_dict.get("Date") or ""
        msg_id = safe_decode_bytes(getattr(m, "messageId", None) or m.getStringStream("__substg1.0_1035") or headers_dict.get("Message-ID") or headers_dict.get("Message-Id") or "").strip()
        in_reply_to = safe_decode_bytes(getattr(m, "inReplyTo", None) or m.getStringStream("__substg1.0_1042") or headers_dict.get("In-Reply-To") or "").strip()
        references = safe_decode_bytes(getattr(m, "references", None) or m.getStringStream("__substg1.0_1039") or headers_dict.get("References") or "").strip()

        # Bodies: HTML, Plain Text, and Compressed RTF
        html_b = ""
        plain_b = ""
        rtf_b = ""
        try:
            html_b = safe_decode_bytes(getattr(m, "htmlBody", None) or m.getStream("__substg1.0_10130102") or "").rstrip("\x00")
        except Exception:
            pass
        try:
            plain_b = safe_decode_bytes(getattr(m, "body", None) or m.getStringStream("__substg1.0_1000") or "").rstrip("\x00")
        except Exception:
            pass
        try:
            raw_rtf = getattr(m, "rtfBody", None) or getattr(m, "compressedRtf", None) or m.getStream("__substg1.0_10090102")
            if raw_rtf:
                rtf_b, rtf_html, rtf_plain = decode_rtf_body(raw_rtf)
                if not html_b and rtf_html:
                    html_b = rtf_html
                if not plain_b and rtf_plain:
                    plain_b = rtf_plain
        except Exception:
            pass

        # Handle Contact .msg items
        if mc_lower.startswith("ipm.contact") or mc_lower.startswith("ipm.distlist"):
            c_name = safe_decode_bytes(getattr(m, "displayName", None) or m.getStringStream("__substg1.0_3001") or subj or "").strip()
            c_email = safe_decode_bytes(getattr(m, "email1EmailAddress", None) or getattr(m, "email1", None) or m.getStringStream("__substg1.0_39FE") or m.getStringStream("__substg1.0_3003") or "").strip()
            self.contacts_raw.append({
                "DisplayName": c_name,
                "EmailAddress": c_email,
                "GivenName": safe_decode_bytes(getattr(m, "givenName", None) or m.getStringStream("__substg1.0_3A06") or ""),
                "Surname": safe_decode_bytes(getattr(m, "surname", None) or m.getStringStream("__substg1.0_3A11") or ""),
                "CompanyName": safe_decode_bytes(getattr(m, "companyName", None) or m.getStringStream("__substg1.0_3A16") or ""),
                "JobTitle": safe_decode_bytes(getattr(m, "jobTitle", None) or m.getStringStream("__substg1.0_3A17") or ""),
                "Department": safe_decode_bytes(getattr(m, "departmentName", None) or m.getStringStream("__substg1.0_3A18") or ""),
                "BusinessPhone": safe_decode_bytes(getattr(m, "businessTelephoneNumber", None) or m.getStringStream("__substg1.0_3A08") or ""),
                "MobilePhone": safe_decode_bytes(getattr(m, "mobileTelephoneNumber", None) or m.getStringStream("__substg1.0_3A1C") or ""),
                "_source_file": source_label
            })
            return

        # Handle Calendar Appointment / Meeting .msg items
        if mc_lower.startswith("ipm.appointment") or mc_lower.startswith("ipm.schedule.meeting"):
            start_dt = getattr(m, "startDate", None) or getattr(m, "appointmentStartWhole", None) or date_val
            end_dt = getattr(m, "endDate", None) or getattr(m, "appointmentEndWhole", None) or start_dt
            loc_str = safe_decode_bytes(getattr(m, "location", None) or "").strip()
            from_parsed = parse_email_address_list(sender)
            self.calendar_raw.append({
                "Subject": subj or conv_topic or "Calendar Appointment",
                "OrganizerName": from_parsed[0]["name"] if from_parsed else sender,
                "OrganizerAddress": from_parsed[0]["email"] if from_parsed else "",
                "Attendees": [r["display"] for r in (to_list + cc_list)],
                "StartTime": start_dt,
                "EndTime": end_dt,
                "Location": loc_str,
                "Body": plain_b or html_to_plain_text(html_b),
                "_source_file": source_label
            })
            if not mc_lower.startswith("ipm.schedule.meeting"):
                return

        atts = []
        for a_idx, att in enumerate(getattr(m, "attachments", []) or []):
            a_name = safe_decode_bytes(getattr(att, "longFilename", None) or getattr(att, "shortFilename", None) or getattr(att, "name", None) or f"msg_att_{a_idx + 1}").rstrip("\x00")
            a_cid = safe_decode_bytes(getattr(att, "cid", None) or getattr(att, "contentId", None) or "").rstrip("\x00")
            a_mime = safe_decode_bytes(getattr(att, "mimetype", None) or "").rstrip("\x00")
            a_data = getattr(att, "data", None)
            if isinstance(a_data, (bytes, bytearray, memoryview)):
                atts.append({
                    "Name": a_name,
                    "ContentType": a_mime,
                    "ContentId": a_cid,
                    "IsInline": bool(a_cid),
                    "Size": len(a_data),
                    "_raw_bytes": bytes(a_data)
                })
            elif a_data is not None and hasattr(a_data, "exportBytes"):
                # Embedded MSG attachment (PR_ATTACH_METHOD == 5)
                if not a_name.lower().endswith(".msg"):
                    a_name += ".msg"
                try:
                    raw_msg_bytes = a_data.exportBytes()
                except Exception:
                    raw_msg_bytes = b""
                atts.append({
                    "Name": a_name,
                    "ContentType": "application/vnd.ms-outlook",
                    "ContentId": a_cid,
                    "IsInline": False,
                    "Size": len(raw_msg_bytes),
                    "_raw_bytes": raw_msg_bytes
                })
                try:
                    self.parse_msg_object(a_data, source_label=f"{source_label}!{a_name}", folder_name=folder_name)
                except Exception:
                    pass

        imp_str = str(getattr(m, "importanceString", None) or "Normal").capitalize()
        if imp_str not in ("High", "Low", "Normal"):
            imp_str = "Normal"

        self.messages_raw.append({
            "Id": msg_id or f"msg_{source_label}_{len(self.messages_raw) + 1}",
            "ItemClass": msg_class,
            "Subject": subj,
            "ConversationTopic": conv_topic,
            "ConversationIndex": conv_idx_hex,
            "InternetMessageId": msg_id,
            "InReplyTo": in_reply_to,
            "References": references,
            "From": sender,
            "ToRecipients": to_list,
            "CcRecipients": cc_list,
            "BccRecipients": bcc_list,
            "DateTimeReceived": date_val,
            "DateTimeSent": date_val,
            "body_html": html_b,
            "body_plain": plain_b,
            "body_rtf": rtf_b[:5000] if rtf_b else "",
            "TransportHeaders": raw_headers_str,
            "ParsedHeaders": headers_dict,
            "FolderName": folder_name,
            "Importance": imp_str,
            "IsRead": bool(getattr(m, "isRead", True)),
            "Attachments": atts,
            "_source_file": source_label
        })

    def parse_msg_file(self, file_path):
        """Parses a standalone Outlook .msg (OLE2 Compound Document) file."""
        try:
            if not os.path.isfile(file_path) or os.path.getsize(file_path) < 32:
                return
            with open(file_path, "rb") as f:
                head = f.read(512)
            # Skip zeroed cloud placeholder files
            if head.count(0) == len(head):
                return
            # If it's actually an RFC 5322 / MIME text email with .msg extension
            if not head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
                head_str = head.decode("utf-8", errors="ignore")
                if any(h in head_str for h in ("From:", "Subject:", "Message-ID:", "Received:", "MIME-Version:")):
                    self.parse_eml_file(file_path)
                return

            self.source_files_ingested.append(file_path)
            import extract_msg
            # Patch extract_msg MSGFile.prefixList for EmbeddedMsgAttachment compatibility
            if not hasattr(extract_msg.MSGFile, "prefixList"):
                extract_msg.MSGFile.prefixList = property(lambda s: list(getattr(s, "prefix", ())))
            m = extract_msg.openMsg(file_path, strict=False, errorBehavior=extract_msg.enums.ErrorBehavior.STANDARDS_VIOLATION)
            try:
                self.parse_msg_object(m, source_label=os.path.basename(file_path), folder_name="Exported MSG")
            finally:
                m.close()
        except Exception as e:
            log_progress(f"  Notice parsing MSG file {os.path.basename(file_path)}: {e}")

    def parse_eml_bytes(self, raw_bytes, source_file="Email.eml", folder_name="Inbox"):
        """Parses an RFC 5322 / MIME email from bytes losslessly."""
        try:
            emsg = email.message_from_bytes(raw_bytes, policy=email.policy.compat32)
            subj = decode_mime_words(emsg.get("Subject", ""))
            from_hdr = decode_mime_words(emsg.get("From", ""))
            to_hdr = decode_mime_words(emsg.get("To", ""))
            cc_hdr = decode_mime_words(emsg.get("Cc", ""))
            bcc_hdr = decode_mime_words(emsg.get("Bcc", ""))
            reply_to_hdr = decode_mime_words(emsg.get("Reply-To", ""))
            date_hdr = decode_mime_words(emsg.get("Date", ""))
            msg_id = decode_mime_words(emsg.get("Message-ID", "") or emsg.get("Message-Id", "")).strip()
            in_reply_to = decode_mime_words(emsg.get("In-Reply-To", "")).strip()
            references = decode_mime_words(emsg.get("References", "")).strip()
            thread_topic = decode_mime_words(emsg.get("Thread-Topic", "")) or subj
            thread_index = decode_mime_words(emsg.get("Thread-Index", "")).strip()
            folder_hdr = decode_mime_words(emsg.get("X-Folder", "") or emsg.get("X-Outlook-Folder", "")) or folder_name
            importance_hdr = decode_mime_words(emsg.get("Importance", "") or emsg.get("X-Priority", "Normal"))

            headers_dict = {}
            raw_hdr_lines = []
            for hk, hv in emsg.items():
                dec_v = decode_mime_words(hv)
                raw_hdr_lines.append(f"{hk}: {dec_v}")
                if hk in headers_dict:
                    headers_dict[hk] += "; " + dec_v
                else:
                    headers_dict[hk] = dec_v

            html_parts = []
            plain_parts = []
            atts = []

            if emsg.is_multipart():
                for part in emsg.walk():
                    if part.is_multipart():
                        continue
                    ctype = (part.get_content_type() or "application/octet-stream").lower()
                    cdisp = str(part.get("Content-Disposition") or "")
                    cid = str(part.get("Content-ID") or "").strip().strip("<>")
                    fname = part.get_filename()
                    if fname:
                        fname = decode_mime_words(fname)
                    payload = part.get_payload(decode=True)
                    if payload is None:
                        raw_p = part.get_payload()
                        if isinstance(raw_p, str):
                            payload = raw_p.encode("utf-8", errors="replace")

                    is_attachment = bool(fname) or ("attachment" in cdisp.lower()) or bool(cid and not ctype.startswith("text/"))
                    if not is_attachment and ctype == "text/html":
                        charset = part.get_content_charset() or "utf-8"
                        html_parts.append(safe_decode_bytes(payload, preferred_encoding=charset))
                    elif not is_attachment and ctype == "text/plain":
                        charset = part.get_content_charset() or "utf-8"
                        plain_parts.append(safe_decode_bytes(payload, preferred_encoding=charset))
                    elif payload:
                        atts.append({
                            "Name": fname or (f"inline_{cid}" if cid else f"part_{len(atts) + 1}"),
                            "ContentType": ctype,
                            "ContentId": cid,
                            "IsInline": bool(cid or "inline" in cdisp.lower()),
                            "Size": len(payload),
                            "_raw_bytes": payload
                        })
            else:
                ctype = (emsg.get_content_type() or "text/plain").lower()
                payload = emsg.get_payload(decode=True)
                charset = emsg.get_content_charset() or "utf-8"
                text_body = safe_decode_bytes(payload, preferred_encoding=charset)
                if ctype == "text/html":
                    html_parts.append(text_body)
                else:
                    plain_parts.append(text_body)

            imp = "Normal"
            if "high" in importance_hdr.lower() or importance_hdr.strip().startswith("1") or importance_hdr.strip().startswith("2"):
                imp = "High"
            elif "low" in importance_hdr.lower() or importance_hdr.strip().startswith("5"):
                imp = "Low"

            self.messages_raw.append({
                "Id": msg_id or f"eml_{source_file}_{len(self.messages_raw) + 1}",
                "ItemClass": "IPM.Note",
                "Subject": subj,
                "ConversationTopic": thread_topic,
                "ConversationIndex": thread_index,
                "InternetMessageId": msg_id,
                "InReplyTo": in_reply_to,
                "References": references,
                "From": from_hdr,
                "ToRecipients": to_hdr,
                "CcRecipients": cc_hdr,
                "BccRecipients": bcc_hdr,
                "ReplyTo": reply_to_hdr,
                "DateTimeReceived": date_hdr,
                "DateTimeSent": date_hdr,
                "body_html": "\n".join(html_parts),
                "body_plain": "\n".join(plain_parts),
                "TransportHeaders": "\n".join(raw_hdr_lines),
                "ParsedHeaders": headers_dict,
                "FolderName": folder_hdr,
                "Importance": imp,
                "Attachments": atts,
                "_source_file": source_file
            })
        except Exception as e:
            log_progress(f"  Notice parsing EML {source_file}: {e}")

    def parse_eml_file(self, file_path):
        try:
            self.source_files_ingested.append(file_path)
            with open(file_path, "rb") as f:
                raw_bytes = f.read()
            parent_folder = os.path.basename(os.path.dirname(file_path))
            folder_guess = parent_folder if parent_folder.lower() in ("inbox", "sent", "sent items", "drafts", "deleted items", "archive", "junk", "junk email") else "Inbox"
            self.parse_eml_bytes(raw_bytes, source_file=os.path.basename(file_path), folder_name=folder_guess)
        except Exception as e:
            log_progress(f"  Warning reading EML file {os.path.basename(file_path)}: {e}")

    def parse_mbox_file(self, file_path):
        try:
            self.source_files_ingested.append(file_path)
            mb = mailbox.mbox(file_path)
            for idx, msg in enumerate(mb):
                self.parse_eml_bytes(msg.as_bytes(), source_file=f"{os.path.basename(file_path)}#{idx + 1}", folder_name=os.path.splitext(os.path.basename(file_path))[0])
            mb.close()
        except Exception as e:
            log_progress(f"  Warning reading MBOX file {os.path.basename(file_path)}: {e}")

    def ingest_json_or_csv_file(self, file_path):
        fl = file_path.lower()
        bname = os.path.basename(file_path)
        if bname.lower() in ("usersettings.json", "manifest.json", "protocols.json", "keys.json", "verified_contents.json", "metadata.json", "outlook_forensic_data.json"):
            return
        try:
            if fl.endswith(".csv"):
                with open(file_path, "r", encoding="utf-8-sig", errors="ignore", newline="") as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        if not isinstance(row, dict):
                            continue
                        if "value" in row and len(row) <= 6:
                            try:
                                v = json.loads(row.get("value", ""))
                                self.ingest_record(row.get("database_id"), row.get("object_store_id"), row.get("user_key"), v, source_file=bname)
                                continue
                            except Exception:
                                pass
                        self.ingest_record("CSV", bname, row.get("id") or row.get("Id"), row, source_file=bname)
            elif fl.endswith(".json"):
                with open(file_path, "r", encoding="utf-8-sig", errors="ignore") as f:
                    text = f.read()
                if not text.strip():
                    return
                try:
                    data = json.loads(text)
                    self.ingest_record("JSON", bname, None, data, source_file=bname)
                except Exception:
                    # Try JSONL (JSON lines)
                    for idx, ln in enumerate(text.splitlines()):
                        ln = ln.strip()
                        if ln.startswith("{") and ln.endswith("}"):
                            try:
                                obj = json.loads(ln)
                                self.ingest_record("JSONL", bname, str(idx), obj, source_file=bname)
                            except Exception:
                                continue
        except Exception as e:
            log_progress(f"  Notice reading {bname}: {e}")

    def ingest_all_sources(self):
        """
        Unified multi-source discovery and ingestion across:
        - New Outlook (Olk) WebView2 LevelDB & IndexedDB directories / .ldb & .log files
        - New Outlook UserSettings.json, xpdApi.log, logs/olk_*.log
        - Classic Outlook .ost and .pst files
        - Standalone .msg, .eml, and .mbox files
        - Pre-extracted .json and .csv forensic dumps
        """
        if os.path.isfile(self.target_path):
            fl = self.target_path.lower()
            if fl.endswith((".pst", ".ost", ".nst")):
                self.parse_pff_file(self.target_path)
            elif fl.endswith(".msg"):
                self.parse_msg_file(self.target_path)
            elif fl.endswith(".eml"):
                self.parse_eml_file(self.target_path)
            elif fl.endswith(".mbox"):
                self.parse_mbox_file(self.target_path)
            elif fl.endswith((".ldb", ".log")):
                if os.path.basename(fl) == "xpdapi.log" or os.path.basename(fl).startswith("olk_"):
                    self.ingest_olk_settings_and_logs(self.target_path)
                else:
                    self.ingest_leveldb_files([], [self.target_path])
            elif fl.endswith((".json", ".csv")):
                if os.path.basename(fl) == "usersettings.json":
                    self.ingest_olk_settings_and_logs(self.target_path)
                else:
                    self.ingest_json_or_csv_file(self.target_path)
            else:
                # Check magic bytes of unknown file
                try:
                    with open(self.target_path, "rb") as f:
                        head = f.read(16)
                    if head.startswith(b"!BDN"):
                        self.parse_pff_file(self.target_path)
                    elif head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
                        self.parse_msg_file(self.target_path)
                    else:
                        self.carve_raw_emails_from_binary(self.target_path)
                except Exception:
                    pass
            log_progress(f"  Single-file ingestion complete: Messages={len(self.messages_raw)}, Calendar={len(self.calendar_raw)}, Contacts={len(self.contacts_raw)}, LevelDB={len(self.leveldb_records)}")
            return

        # Directory walk
        leveldb_dirs = []
        standalone_ldb_files = []
        pff_files = []
        msg_files = []
        eml_files = []
        mbox_files = []
        json_csv_files = []

        skip_dirs = {
            "$recycle.bin", "system volume information", "windows", "program files", "program files (x86)",
            ".git", "node_modules", "cases", "code cache", "gpucache", "shadercache", "grshadercache",
            "dawngraphitecache", "dawnwebgpucache", "component_crx_cache", "extensions_crx_cache",
            "speech recognition", "subresource filter", "hyphen-data", "trusttokenkeycommitments",
            "certificateRevocation", "pkimetadata", "meipreload", "autofillaimodelcache"
        }

        # 1. Ingest Olk UserSettings.json and logs if present
        self.ingest_olk_settings_and_logs(self.target_path)

        for root, dirs, files in os.walk(self.target_path):
            dirs[:] = [d for d in dirs if d.lower() not in skip_dirs]
            r_lower = root.lower()
            if r_lower.endswith(".blob"):
                continue

            has_ldb = any(f.lower().endswith(".ldb") for f in files)
            is_ldb_dir = (
                r_lower.endswith(".indexeddb.leveldb")
                or os.path.basename(r_lower) == "leveldb"
                or os.path.basename(r_lower) in ("local storage", "session storage")
                or has_ldb
                or ("CURRENT" in files and any(f.lower().endswith(".log") for f in files))
            )
            if is_ldb_dir and root not in leveldb_dirs:
                leveldb_dirs.append(root)

            for f in files:
                fl = f.lower()
                fp = os.path.join(root, f)
                if fl.endswith((".pst", ".ost", ".nst")):
                    pff_files.append(fp)
                elif fl.endswith(".msg"):
                    msg_files.append(fp)
                elif fl.endswith(".eml"):
                    eml_files.append(fp)
                elif fl.endswith(".mbox"):
                    mbox_files.append(fp)
                elif fl.endswith((".ldb", ".log")) and root not in leveldb_dirs:
                    if fl not in ("xpdapi.log", "favorites_diagnostic.log", "log", "log.old") and not fl.startswith("olk_"):
                        standalone_ldb_files.append(fp)
                elif fl.endswith((".json", ".csv")):
                    if fl not in ("usersettings.json", "manifest.json", "protocols.json", "keys.json", "verified_contents.json", "metadata.json"):
                        json_csv_files.append(fp)

        # Sort LevelDB directories so Outlook / IndexedDB tables come first
        def ldb_priority(d):
            dl = d.lower()
            if "outlook" in dl and "indexeddb" in dl:
                return 0
            if "indexeddb" in dl:
                return 1
            if "local storage" in dl or "session storage" in dl or "sync data" in dl:
                return 2
            return 3
        leveldb_dirs.sort(key=ldb_priority)

        if leveldb_dirs or standalone_ldb_files:
            self.ingest_leveldb_files(leveldb_dirs, standalone_ldb_files)

        for pf in pff_files:
            self.parse_pff_file(pf)

        for mf in msg_files:
            self.parse_msg_file(mf)

        for ef in eml_files:
            self.parse_eml_file(ef)

        for mbf in mbox_files:
            self.parse_mbox_file(mbf)

        for jcf in json_csv_files:
            self.ingest_json_or_csv_file(jcf)

        log_progress(
            f"  Ingestion Summary: Raw Messages={len(self.messages_raw)}, "
            f"Conversations={len(self.conv_meta_raw)}, Folders={len(self.folders_map)}, "
            f"Calendar={len(self.calendar_raw)}, Contacts={len(self.contacts_raw)}, "
            f"LevelDB/Olk Records={len(self.leveldb_records)}"
        )

    def process_contacts_and_accounts(self):
        """Builds the contacts lookup dictionary and resolves the primary custodian mailbox account."""
        for c in self.contacts_raw:
            if not isinstance(c, dict):
                continue
            name = (
                c.get("DisplayName") or c.get("displayName")
                or c.get("Name") or c.get("name")
                or f"{c.get('GivenName') or c.get('givenName') or ''} {c.get('Surname') or c.get('surname') or ''}".strip()
            )
            email_val = c.get("EmailAddress") or c.get("emailAddress") or c.get("UserPrincipalName") or c.get("userPrincipalName") or c.get("ImAddress") or c.get("imAddress") or ""
            if isinstance(email_val, dict):
                email_val = email_val.get("Address") or email_val.get("address") or email_val.get("EmailAddress") or ""
            if not email_val:
                e_list = c.get("EmailAddresses") or c.get("emailAddresses") or []
                if isinstance(e_list, list) and e_list:
                    first_e = e_list[0]
                    if isinstance(first_e, dict):
                        email_val = first_e.get("Address") or first_e.get("address") or first_e.get("EmailAddress") or ""
                    elif isinstance(first_e, str):
                        email_val = first_e

            name_str = decode_mime_words(str(name or "")).strip()
            email_str = decode_mime_words(str(email_val or "")).strip().lower()
            if not name_str and email_str:
                name_str = " ".join(p.capitalize() for p in re.split(r'[._\-]+', email_str.split("@")[0]) if p)
            if not name_str and not email_str:
                continue

            company = str(c.get("CompanyName") or c.get("companyName") or (email_str.split("@")[-1] if "@" in email_str else "")).strip()
            dept = str(c.get("Department") or c.get("department") or "").strip()
            role = str(c.get("JobTitle") or c.get("jobTitle") or c.get("PersonaType") or "").strip()
            phone = str(c.get("BusinessPhone") or c.get("MobilePhone") or c.get("Phones") or c.get("phones") or "").strip()
            pid = str(c.get("PersonaId") or c.get("personaId") or c.get("Id") or c.get("id") or email_str or name_str).strip()
            if isinstance(c.get("PersonaId"), dict):
                pid = str(c["PersonaId"].get("Id") or pid)

            entry = {
                "name": name_str,
                "email": email_str,
                "role": role,
                "department": dept,
                "company": company,
                "phone": phone,
                "persona_id": pid,
                "sent_count": 0,
                "received_count": 0,
                "source": str(c.get("_source_file") or "Directory")
            }
            if email_str:
                self.contacts_dict[email_str] = entry
            if name_str:
                self.contacts_dict[name_str.lower()] = entry

        # Also check Conversation metadata for folder mappings
        for cid, cmeta in self.conv_meta_raw.items():
            if not isinstance(cmeta, dict):
                continue
            topic = cmeta.get("ConversationTopic") or cmeta.get("conversationTopic") or cmeta.get("Subject") or ""
            cmeta["_clean_topic"] = decode_mime_words(str(topic)).strip()

        log_progress(f"  Indexed {len(self.contacts_dict)} initial directory contact lookup keys.")

    def extract_body_fields(self, raw_msg):
        """Extracts both HTML body and Plain Text body from any EWS/OWA/Graph/MAPI message schema."""
        html_candidates = []
        plain_candidates = []

        for k in ("body_html", "BodyHtml", "htmlBody", "HtmlBody"):
            v = raw_msg.get(k)
            if v and isinstance(v, str) and v.strip():
                html_candidates.append(v)

        for k in ("body_plain", "BodyPlain", "plainTextBody", "PlainTextBody", "textBody", "TextBody"):
            v = raw_msg.get(k)
            if v and isinstance(v, str) and v.strip():
                plain_candidates.append(v)

        for k in ("NormalizedBody", "normalizedBody", "Body", "body", "UniqueBody", "uniqueBody", "Content", "content"):
            b_obj = raw_msg.get(k)
            if isinstance(b_obj, dict):
                b_val = b_obj.get("Value") or b_obj.get("value") or b_obj.get("content") or b_obj.get("Content") or ""
                b_type = str(b_obj.get("BodyType") or b_obj.get("bodyType") or b_obj.get("contentType") or b_obj.get("ContentType") or "HTML").upper()
                if b_val and isinstance(b_val, str):
                    if "HTML" in b_type or "<html" in b_val.lower() or "<div" in b_val.lower() or "<p>" in b_val.lower() or "<table" in b_val.lower():
                        html_candidates.append(b_val)
                    else:
                        plain_candidates.append(b_val)
            elif isinstance(b_obj, str) and b_obj.strip():
                if "<html" in b_obj.lower() or "<body" in b_obj.lower() or "<div" in b_obj.lower() or "<p>" in b_obj.lower() or "<table" in b_obj.lower() or "<br" in b_obj.lower():
                    html_candidates.append(b_obj)
                else:
                    plain_candidates.append(b_obj)

        for k in ("BodyPreview", "bodyPreview", "Preview", "preview"):
            pv = raw_msg.get(k)
            if pv and isinstance(pv, str) and pv.strip():
                plain_candidates.append(pv)

        best_html = max(html_candidates, key=len) if html_candidates else ""
        best_plain = max(plain_candidates, key=len) if plain_candidates else ""

        if best_html and not best_plain:
            best_plain = html_to_plain_text(best_html)

        return best_html, best_plain

    def process_messages(self):
        """Normalizes and deduplicates all ingested email messages and extracts embedded attachments."""
        for idx, m in enumerate(self.messages_raw):
            if not isinstance(m, dict):
                continue

            # 1. Message IDs
            raw_id = m.get("ItemId") or m.get("itemId") or m.get("Id") or m.get("id") or m.get("clientMessageId") or m.get("_ukey")
            if isinstance(raw_id, dict):
                raw_id = raw_id.get("Id") or raw_id.get("id")
            msg_id = str(raw_id or f"msg_{idx + 1}").strip().strip('"')

            inet_msg_id = str(
                m.get("InternetMessageId") or m.get("internetMessageId")
                or m.get("MessageId") or m.get("messageId")
                or m.get("Message-ID") or ""
            ).strip()

            in_reply_to = str(
                m.get("InReplyTo") or m.get("inReplyTo") or m.get("In-Reply-To") or ""
            ).strip()

            refs_raw = m.get("References") or m.get("references") or ""
            if isinstance(refs_raw, list):
                refs_str = " ".join(str(x) for x in refs_raw)
            else:
                refs_str = str(refs_raw).strip()

            # Check transport headers if InternetMessageId / InReplyTo / References are missing
            parsed_hdrs = m.get("ParsedHeaders") if isinstance(m.get("ParsedHeaders"), dict) else {}
            raw_hdrs = m.get("TransportHeaders") or m.get("transportHeaders") or m.get("InternetMessageHeaders") or m.get("internetMessageHeaders") or ""
            if isinstance(raw_hdrs, list):
                hdr_lines = []
                for h_item in raw_hdrs:
                    if isinstance(h_item, dict):
                        hk = h_item.get("HeaderName") or h_item.get("headerName") or h_item.get("name") or h_item.get("Name") or ""
                        hv = h_item.get("HeaderValue") or h_item.get("headerValue") or h_item.get("value") or h_item.get("Value") or ""
                        if hk:
                            dec_v = decode_mime_words(str(hv))
                            parsed_hdrs[hk] = dec_v
                            hdr_lines.append(f"{hk}: {dec_v}")
                raw_hdrs_str = "\n".join(hdr_lines)
            elif isinstance(raw_hdrs, dict):
                for hk, hv in raw_hdrs.items():
                    parsed_hdrs[str(hk)] = decode_mime_words(str(hv))
                raw_hdrs_str = "\n".join(f"{k}: {v}" for k, v in parsed_hdrs.items())
            else:
                raw_hdrs_str = str(raw_hdrs or "")
                if raw_hdrs_str and not parsed_hdrs and ":" in raw_hdrs_str:
                    try:
                        emsg = email.message_from_string(raw_hdrs_str)
                        for hk, hv in emsg.items():
                            parsed_hdrs[hk] = decode_mime_words(hv)
                    except Exception:
                        pass

            if not inet_msg_id:
                inet_msg_id = parsed_hdrs.get("Message-ID") or parsed_hdrs.get("Message-Id") or ""
            if not in_reply_to:
                in_reply_to = parsed_hdrs.get("In-Reply-To") or ""
            if not refs_str:
                refs_str = parsed_hdrs.get("References") or ""

            # Extract list of RFC 5322 <message-id> tokens
            def extract_mid_tokens(s):
                if not s:
                    return []
                angled = re.findall(r'<([^<>\s]+)>', s)
                if angled:
                    return [a.strip().lower() for a in angled if a.strip()]
                return [t.strip("<>").lower() for t in re.split(r'[\s,;]+', s) if t.strip("<>")]

            inet_tokens = extract_mid_tokens(inet_msg_id)
            canonical_inet_id = inet_tokens[0] if inet_tokens else inet_msg_id.strip("<>").lower()
            reply_tokens = extract_mid_tokens(in_reply_to)
            canonical_reply_to = reply_tokens[0] if reply_tokens else in_reply_to.strip("<>").lower()
            refs_tokens = extract_mid_tokens(refs_str)

            # 2. Conversation ID & MAPI ConversationIndex
            conv_id_raw = m.get("ConversationId") or m.get("conversationId") or m.get("ThreadId") or m.get("threadId") or ""
            if isinstance(conv_id_raw, dict):
                conv_id_raw = conv_id_raw.get("Id") or conv_id_raw.get("id") or ""
            conv_id = str(conv_id_raw).strip().strip('"')

            conv_idx_raw = m.get("ConversationIndex") or m.get("conversationIndex") or parsed_hdrs.get("Thread-Index") or ""
            conv_idx_info = parse_mapi_conversation_index(conv_idx_raw)

            # 3. Subject & Conversation Topic
            subj_raw = m.get("Subject") or m.get("subject") or parsed_hdrs.get("Subject") or ""
            topic_raw = m.get("ConversationTopic") or m.get("conversationTopic") or parsed_hdrs.get("Thread-Topic") or subj_raw
            subject = decode_mime_words(str(subj_raw)).strip() or decode_mime_words(str(topic_raw)).strip() or "(No Subject)"
            conv_topic = decode_mime_words(str(topic_raw)).strip() or normalize_subject(subject)
            norm_subj = normalize_subject(conv_topic or subject)

            # 4. Sender & Recipients
            from_raw = m.get("From") or m.get("from") or m.get("Sender") or m.get("sender") or parsed_hdrs.get("From")
            if not from_raw and (m.get("sender_name") or m.get("sender_email") or m.get("imDisplayName")):
                from_raw = {"name": m.get("sender_name") or m.get("imDisplayName") or "", "address": m.get("sender_email") or m.get("creator") or ""}
            from_list = parse_email_address_list(from_raw)
            sender_name = from_list[0]["name"] if from_list else "Unknown Sender"
            sender_email = from_list[0]["email"] if from_list else ""
            sender_display = from_list[0]["display"] if from_list else sender_name

            # Resolve against directory if needed
            if sender_email and sender_email in self.contacts_dict and (not sender_name or sender_name == sender_email):
                sender_name = self.contacts_dict[sender_email]["name"]
                sender_display = f"{sender_name} <{sender_email}>"
            elif sender_name.lower() in self.contacts_dict and (not sender_email or "/o=" in sender_email.lower()):
                c_match = self.contacts_dict[sender_name.lower()]
                if c_match.get("email"):
                    sender_email = c_match["email"]
                    sender_display = f"{sender_name} <{sender_email}>"

            to_list = parse_email_address_list(
                m.get("ToRecipients") or m.get("toRecipients") or m.get("DisplayTo") or m.get("displayTo") or m.get("to") or parsed_hdrs.get("To")
            )
            cc_list = parse_email_address_list(
                m.get("CcRecipients") or m.get("ccRecipients") or m.get("DisplayCc") or m.get("displayCc") or m.get("cc") or parsed_hdrs.get("Cc")
            )
            bcc_list = parse_email_address_list(
                m.get("BccRecipients") or m.get("bccRecipients") or m.get("DisplayBcc") or m.get("displayBcc") or m.get("bcc") or parsed_hdrs.get("Bcc")
            )
            reply_to_list = parse_email_address_list(
                m.get("ReplyTo") or m.get("replyTo") or parsed_hdrs.get("Reply-To")
            )

            # 5. Timestamps
            t_recv_raw = (
                m.get("DateTimeReceived") or m.get("dateTimeReceived")
                or m.get("ReceivedDateTime") or m.get("receivedDateTime")
                or m.get("deliveryTime") or m.get("originalArrivalTime")
                or m.get("DateTimeSent") or m.get("dateTimeSent")
                or m.get("SentDateTime") or m.get("sentDateTime")
                or m.get("DateTimeCreated") or m.get("createdDateTime")
                or m.get("LastModifiedTime") or m.get("lastModifiedDateTime")
                or parsed_hdrs.get("Date") or m.get("timestamp")
            )
            t_sent_raw = (
                m.get("DateTimeSent") or m.get("dateTimeSent")
                or m.get("SentDateTime") or m.get("sentDateTime")
                or m.get("composeTime") or t_recv_raw
            )
            time_utc, time_local, time_sort = format_time(t_recv_raw)
            if not time_utc and conv_idx_info.get("header_time_utc"):
                time_utc, time_local, time_sort = format_time(conv_idx_info["header_time_utc"])
            sent_utc, sent_local, _ = format_time(t_sent_raw)

            # 6. Folder Resolution
            folder_id_raw = m.get("ParentFolderId") or m.get("parentFolderId") or m.get("FolderId") or m.get("folderId") or ""
            if isinstance(folder_id_raw, dict):
                folder_id_raw = folder_id_raw.get("Id") or folder_id_raw.get("id") or ""
            folder_name_raw = m.get("FolderName") or m.get("folderName") or m.get("folder") or ""
            folder_name = self.normalize_folder_name(folder_name_raw, folder_id=str(folder_id_raw))

            # 7. Bodies
            body_html, body_plain = self.extract_body_fields(m)

            # 8. Flags & Properties
            is_read = m.get("IsRead") if m.get("IsRead") is not None else (m.get("isRead") if m.get("isRead") is not None else True)
            is_draft = bool(m.get("IsDraft") or m.get("isDraft") or folder_name == "Drafts")
            is_deleted = bool(m.get("IsDeleted") or m.get("isDeleted") or m.get("deletetime") or folder_name in ("Deleted Items", "[Recovered Orphan Items]"))
            importance = str(m.get("Importance") or m.get("importance") or "Normal").capitalize()
            sensitivity = str(m.get("Sensitivity") or m.get("sensitivity") or "Normal").capitalize()
            categories = m.get("Categories") or m.get("categories") or []
            if isinstance(categories, str):
                categories = [c.strip() for c in categories.split(";") if c.strip()]
            item_class = str(m.get("ItemClass") or m.get("itemClass") or m.get("MessageClass") or "IPM.Note")
            source_file = str(m.get("_source_file") or "Outlook Evidence")

            # 9. Deduplication Check (merge if same message ID in same folder was updated in LevelDB)
            dedup_key = (canonical_inet_id or msg_id, folder_name)
            if dedup_key in self.messages_by_key:
                existing = self.messages_by_key[dedup_key]
                if len(body_html) > len(existing["body_html"]):
                    existing["body_html"] = body_html
                if len(body_plain) > len(existing["body_plain"]):
                    existing["body_plain"] = body_plain
                if is_deleted:
                    existing["is_deleted"] = True
                if not existing["time_utc"] and time_utc:
                    existing["time_utc"] = time_utc
                    existing["time_local"] = time_local
                    existing["time_sort"] = time_sort
                if not existing["to_recipients"] and to_list:
                    existing["to_recipients"] = to_list
                if not existing["raw_attachments"] and (m.get("Attachments") or m.get("attachments")):
                    existing["raw_attachments"] = m.get("Attachments") or m.get("attachments") or []
                continue

            msg_record = {
                "id": msg_id,
                "seq_order": idx,
                "item_class": item_class,
                "internet_message_id": inet_msg_id or (f"<{canonical_inet_id}>" if canonical_inet_id else ""),
                "canonical_inet_id": canonical_inet_id,
                "in_reply_to": in_reply_to,
                "canonical_reply_to": canonical_reply_to,
                "references": refs_str,
                "references_list": refs_tokens,
                "conversation_id": conv_id,
                "conversation_topic": conv_topic,
                "conversation_index": conv_idx_info["hex"],
                "conv_index_guid": conv_idx_info["thread_guid"],
                "conv_index_depth": conv_idx_info["reply_depth"],
                "subject": subject,
                "norm_subject": norm_subj,
                "sender_name": sender_name,
                "sender_email": sender_email,
                "sender_display": sender_display,
                "to_recipients": to_list,
                "cc_recipients": cc_list,
                "bcc_recipients": bcc_list,
                "reply_to": reply_to_list,
                "time_utc": time_utc,
                "time_local": time_local,
                "time_sort": time_sort,
                "sent_utc": sent_utc,
                "sent_local": sent_local,
                "folder": folder_name,
                "folder_id": str(folder_id_raw),
                "importance": importance,
                "sensitivity": sensitivity,
                "is_read": bool(is_read),
                "is_draft": is_draft,
                "is_deleted": is_deleted,
                "categories": categories,
                "body_html": body_html,
                "body_plain": body_plain,
                "body_rtf": str(m.get("body_rtf") or ""),
                "transport_headers": raw_hdrs_str,
                "parsed_headers": parsed_hdrs,
                "mapi_properties": m.get("MapiProperties") or {},
                "raw_attachments": m.get("Attachments") or m.get("attachments") or [],
                "attachments": [],
                "source_file": source_file
            }
            self.messages_by_key[dedup_key] = msg_record

        self.all_messages_list = list(self.messages_by_key.values())

        # Now process attachments for each deduplicated message
        for msg in self.all_messages_list:
            raw_atts = msg.pop("raw_attachments", [])
            if isinstance(raw_atts, str):
                try:
                    raw_atts = json.loads(raw_atts)
                except Exception:
                    raw_atts = []
            if not isinstance(raw_atts, list):
                raw_atts = []

            msg_meta = {
                "msg_id": msg["id"],
                "subject": msg["subject"],
                "sender": msg["sender_display"],
                "time_local": msg["time_local"],
                "folder": msg["folder"],
                "source_file": msg["source_file"]
            }

            for a_item in raw_atts:
                if not isinstance(a_item, dict):
                    continue
                a_name = (
                    a_item.get("Name") or a_item.get("name")
                    or a_item.get("FileName") or a_item.get("fileName")
                    or a_item.get("DisplayName") or a_item.get("displayName")
                    or "attachment"
                )
                a_ctype = a_item.get("ContentType") or a_item.get("contentType") or ""
                a_cid = a_item.get("ContentId") or a_item.get("contentId") or a_item.get("cid") or ""
                a_inline = bool(a_item.get("IsInline") or a_item.get("isInline") or a_cid)
                a_size = int(a_item.get("Size") or a_item.get("size") or 0)
                msg_meta["declared_size"] = a_size

                a_bytes = a_item.get("_raw_bytes")
                if a_bytes is None:
                    b64_str = a_item.get("ContentBytes") or a_item.get("contentBytes") or a_item.get("data") or a_item.get("base64")
                    if isinstance(b64_str, str) and b64_str.strip():
                        try:
                            a_bytes = base64.b64decode(b64_str)
                        except Exception:
                            a_bytes = b64_str.encode("utf-8", errors="replace")
                    elif isinstance(b64_str, (bytes, bytearray)):
                        a_bytes = bytes(b64_str)

                att_rec = self.save_attachment_bytes(
                    orig_filename=a_name,
                    data_bytes=a_bytes,
                    content_type=a_ctype,
                    content_id=a_cid,
                    is_inline=a_inline,
                    msg_meta=msg_meta
                )
                msg["attachments"].append(att_rec)

            # Update contact sent/received counters & auto-discover contacts from emails
            s_email = msg["sender_email"]
            s_name = msg["sender_name"]
            if s_email or (s_name and s_name != "Unknown Sender"):
                ckey = s_email if s_email else s_name.lower()
                if ckey not in self.contacts_dict:
                    self.contacts_dict[ckey] = {
                        "name": s_name or s_email,
                        "email": s_email,
                        "role": "Email Correspondent",
                        "department": "",
                        "company": s_email.split("@")[-1] if "@" in s_email else "",
                        "phone": "",
                        "persona_id": ckey,
                        "sent_count": 0,
                        "received_count": 0,
                        "source": msg["source_file"]
                    }
                self.contacts_dict[ckey]["sent_count"] = self.contacts_dict[ckey].get("sent_count", 0) + 1

            for r in (msg["to_recipients"] + msg["cc_recipients"] + msg["bcc_recipients"]):
                r_email = r.get("email", "")
                r_name = r.get("name", "")
                if r_email or r_name:
                    rkey = r_email if r_email else r_name.lower()
                    if rkey not in self.contacts_dict:
                        self.contacts_dict[rkey] = {
                            "name": r_name or r_email,
                            "email": r_email,
                            "role": "Email Correspondent",
                            "department": "",
                            "company": r_email.split("@")[-1] if "@" in r_email else "",
                            "phone": "",
                            "persona_id": rkey,
                            "sent_count": 0,
                            "received_count": 0,
                            "source": msg["source_file"]
                        }
                    self.contacts_dict[rkey]["received_count"] = self.contacts_dict[rkey].get("received_count", 0) + 1

        # Determine primary user if not yet resolved from UserSettings.json
        if self.primary_user == "Outlook Account":
            # Check sender of Sent Items first
            sent_senders = Counter()
            all_participants = Counter()
            for msg in self.all_messages_list:
                if msg["folder"] == "Sent Items" and (msg["sender_email"] or msg["sender_name"]):
                    sent_senders[(msg["sender_name"], msg["sender_email"])] += 1
                if msg["sender_email"]:
                    all_participants[(msg["sender_name"], msg["sender_email"])] += 1
                for r in msg["to_recipients"]:
                    if r.get("email"):
                        all_participants[(r.get("name", ""), r["email"])] += 1
            if sent_senders:
                (p_name, p_email), _ = sent_senders.most_common(1)[0]
                self.primary_user = p_name or p_email
                self.primary_email = p_email
            elif all_participants:
                (p_name, p_email), _ = all_participants.most_common(1)[0]
                self.primary_user = p_name or p_email
                self.primary_email = p_email
            if self.primary_email and "@" in self.primary_email:
                self.primary_tenant = self.primary_email.split("@")[-1].split(".")[0].upper()

        log_progress(f"  Normalized {len(self.all_messages_list)} unique email messages and {len(self.attachments_catalog)} direct attachments.")

    def extract_cached_media_and_link_cids(self):
        """
        1. Scans any IndexedDB .indexeddb.blob folders or WebView2 Cache_Data folders inside self.target_path
           for cached attachments/images.
        2. Links unextracted attachment references by filename.
        3. Rewrites inline cid:... image references in HTML bodies to local extracted attachment paths.
        """
        if os.path.isdir(self.target_path):
            blob_dirs = []
            for root, dirs, files in os.walk(self.target_path):
                rl = root.lower()
                bl = os.path.basename(rl)
                if bl.endswith(".indexeddb.blob"):
                    blob_dirs.append(root)

            for b_dir in blob_dirs:
                for root, dirs, files in os.walk(b_dir):
                    for f in files:
                        if f.startswith("$") or f.endswith(".tmp"):
                            continue
                        fp = os.path.join(root, f)
                        try:
                            if os.path.getsize(fp) < 64 or os.path.getsize(fp) > 100 * 1024 * 1024:
                                continue
                            with open(fp, "rb") as bf:
                                raw_b = bf.read()
                            det_mime, det_ext, cat = self.detect_mime_and_ext(raw_b, f)
                            if det_mime != "application/octet-stream":
                                rel_sub = os.path.relpath(fp, b_dir).replace("\\", "_").replace("/", "_")
                                self.save_attachment_bytes(
                                    orig_filename=f"IndexedDB_Blob_{rel_sub}{det_ext}",
                                    data_bytes=raw_b,
                                    content_type=det_mime,
                                    is_inline=False,
                                    msg_meta={"source_file": "IndexedDB.Blob"}
                                )
                        except Exception:
                            continue

        # Build global attachment lookup by filename and contentId
        by_cid = {}
        by_name = {}
        for att in self.attachments_catalog:
            if att.get("extracted") and att.get("rel_path"):
                if att.get("contentId"):
                    cid_clean = att["contentId"].strip("<>").lower()
                    by_cid[cid_clean] = att["rel_path"]
                    by_cid[cid_clean.split("@")[0]] = att["rel_path"]
                if att.get("fileName"):
                    fn_clean = att["fileName"].strip().lower()
                    by_name[fn_clean] = att["rel_path"]

        # Link unextracted metadata-only attachments if a matching file was extracted, and sanitize HTML bodies
        for msg in self.all_messages_list:
            local_cid_map = dict(by_cid)
            for att in msg.get("attachments", []):
                if not att.get("extracted") and att.get("fileName"):
                    fn_lower = att["fileName"].strip().lower()
                    if fn_lower in by_name:
                        att["rel_path"] = by_name[fn_lower]
                        att["extracted"] = True
                if att.get("rel_path"):
                    if att.get("contentId"):
                        c_id = att["contentId"].strip("<>").lower()
                        local_cid_map[c_id] = att["rel_path"]
                        local_cid_map[c_id.split("@")[0]] = att["rel_path"]
                    if att.get("fileName"):
                        fn_l = att["fileName"].strip().lower()
                        local_cid_map[fn_l] = att["rel_path"]

            if msg["body_html"]:
                msg["body_html_clean"] = sanitize_email_html_for_viewer(msg["body_html"], cid_map=local_cid_map)
            else:
                msg["body_html_clean"] = ""

    def build_mail_chains(self):
        """
        Reconstructs complete Mail Chains (conversation threads) using Multi-Signal Union-Find:
          1. Explicit ConversationId (New Outlook IndexedDB / EWS / MAPI 0x3013)
          2. MAPI ConversationIndex 16-byte Thread GUID (bytes 6..22 of PR_CONVERSATION_INDEX)
          3. RFC 5322 Message-ID / In-Reply-To / References dependency graph
          4. Normalized Subject + participant overlap (for replies/forwards without message-id headers)
        Orders messages chronologically within each chain and computes reply depth & parent message links.
        """
        n = len(self.all_messages_list)
        if n == 0:
            self.mail_chains = []
            self.mail_chains_map = {}
            return

        parent = list(range(n))

        def find(i):
            while parent[i] != i:
                parent[i] = parent[parent[i]]
                i = parent[i]
            return i

        def union(i, j):
            ri, rj = find(i), find(j)
            if ri != rj:
                if ri < rj:
                    parent[rj] = ri
                else:
                    parent[ri] = rj

        # Index 1: By explicit ConversationId
        by_conv_id = {}
        # Index 2: By MAPI ConversationIndex 16-byte GUID
        by_conv_guid = {}
        # Index 3: By RFC 5322 Message-ID token (both canonical_inet_id and any referenced Message-ID)
        by_inet_id = {}

        for idx, msg in enumerate(self.all_messages_list):
            cid = msg.get("conversation_id", "").strip()
            if cid:
                if cid in by_conv_id:
                    union(idx, by_conv_id[cid])
                else:
                    by_conv_id[cid] = idx

            cguid = msg.get("conv_index_guid", "").strip()
            if cguid:
                if cguid in by_conv_guid:
                    union(idx, by_conv_guid[cguid])
                else:
                    by_conv_guid[cguid] = idx

            inet_id = msg.get("canonical_inet_id", "").strip()
            if inet_id:
                if inet_id in by_inet_id:
                    union(idx, by_inet_id[inet_id])
                else:
                    by_inet_id[inet_id] = idx

        # Link via In-Reply-To and References tokens (including virtual nodes for missing intermediate emails)
        for idx, msg in enumerate(self.all_messages_list):
            ref_tokens = []
            if msg.get("canonical_reply_to"):
                ref_tokens.append(msg["canonical_reply_to"])
            for rt in msg.get("references_list", []):
                if rt and rt not in ref_tokens:
                    ref_tokens.append(rt)
            for tok in ref_tokens:
                if tok in by_inet_id:
                    union(idx, by_inet_id[tok])
                else:
                    by_inet_id[tok] = idx

        # Index 4: Subject + Participant correlation for messages that share normalized subject
        by_norm_subj = defaultdict(list)
        for idx, msg in enumerate(self.all_messages_list):
            ns = msg.get("norm_subject", "").strip().lower()
            if ns and ns != "(no subject)" and len(ns) >= 3:
                by_norm_subj[ns].append(idx)

        for ns, indices in by_norm_subj.items():
            if len(indices) <= 1:
                continue
            # Collect participant sets for each message with this normalized subject
            def get_msg_participants(m):
                p = set()
                if m.get("sender_email"):
                    p.add(m["sender_email"].lower())
                elif m.get("sender_name"):
                    p.add(m["sender_name"].lower())
                for r in (m.get("to_recipients", []) + m.get("cc_recipients", [])):
                    if r.get("email"):
                        p.add(r["email"].lower())
                    elif r.get("name"):
                        p.add(r["name"].lower())
                return p

            first_idx = indices[0]
            first_parts = get_msg_participants(self.all_messages_list[first_idx])
            for other_idx in indices[1:]:
                m_other = self.all_messages_list[other_idx]
                other_parts = get_msg_participants(m_other)
                subj_raw = m_other.get("subject", "").strip()
                has_re_fw = bool(re.match(r'^(?:re|fw|fwd|aw|wg)\b', subj_raw, re.IGNORECASE))
                if (first_parts & other_parts) or has_re_fw or len(ns) >= 12:
                    union(first_idx, other_idx)
                    first_parts |= other_parts

        # Group messages by connected component root
        components = defaultdict(list)
        for idx in range(n):
            components[find(idx)].append(self.all_messages_list[idx])

        self.mail_chains = []
        for comp_idx, msgs in components.items():
            # Sort messages inside the chain chronologically (oldest first), with conv_index_depth & seq_order as tie-breakers
            msgs.sort(key=lambda m: (
                m.get("time_sort") or "9999-99-99",
                m.get("conv_index_depth") or 0,
                m.get("seq_order") or 0
            ))

            # Build intra-chain Message-ID lookup to resolve exact parent_msg_id and reply_depth
            chain_inet_map = {}
            for m in msgs:
                if m.get("canonical_inet_id"):
                    chain_inet_map[m["canonical_inet_id"]] = m

            # Pick canonical chain_id and subject
            chain_id = ""
            for m in msgs:
                if m.get("conversation_id"):
                    chain_id = m["conversation_id"]
                    break
            if not chain_id:
                for m in msgs:
                    if m.get("conv_index_guid"):
                        chain_id = f"thread_{m['conv_index_guid'][:16]}"
                        break
            if not chain_id:
                chain_id = f"chain_{comp_idx + 1}_{msgs[0]['id']}"

            chain_subject = msgs[0].get("norm_subject") or msgs[0].get("subject") or "(No Subject)"
            if chain_id in self.conv_meta_raw and self.conv_meta_raw[chain_id].get("_clean_topic"):
                chain_subject = self.conv_meta_raw[chain_id]["_clean_topic"]

            participants_ordered = []
            seen_part_keys = set()
            senders_ordered = []
            seen_senders = set()
            folders_ordered = []
            chain_attachments = []
            has_unread = False
            has_deleted = False
            has_draft = False
            highest_imp = "Normal"

            for pos, m in enumerate(msgs):
                m["chain_id"] = chain_id
                m["chain_index"] = pos + 1
                m["chain_total"] = len(msgs)

                # Resolve parent message and reply depth
                parent_id = ""
                depth = m.get("conv_index_depth") or 0
                rep_tok = m.get("canonical_reply_to")
                if rep_tok and rep_tok in chain_inet_map:
                    parent_m = chain_inet_map[rep_tok]
                    parent_id = parent_m["id"]
                    depth = max(depth, (parent_m.get("reply_depth") or 0) + 1)
                elif pos > 0 and depth == 0:
                    # Check references list
                    for rtok in reversed(m.get("references_list", [])):
                        if rtok in chain_inet_map and chain_inet_map[rtok]["id"] != m["id"]:
                            parent_m = chain_inet_map[rtok]
                            parent_id = parent_m["id"]
                            depth = (parent_m.get("reply_depth") or 0) + 1
                            break
                    if not parent_id and pos > 0:
                        parent_id = msgs[pos - 1]["id"]
                        depth = min(pos, 5)

                m["parent_msg_id"] = parent_id
                m["reply_depth"] = min(depth, 6)

                # Update attachment chain_id
                for att in m.get("attachments", []):
                    att["chain_id"] = chain_id
                    chain_attachments.append(att)

                # Collect senders & participants
                s_name = m.get("sender_name") or m.get("sender_email") or "Unknown"
                if s_name not in seen_senders:
                    seen_senders.add(s_name)
                    senders_ordered.append(s_name)

                for p_entry in ([{
                    "name": m.get("sender_name", ""),
                    "email": m.get("sender_email", ""),
                    "display": m.get("sender_display", "")
                }] + m.get("to_recipients", []) + m.get("cc_recipients", [])):
                    pkey = (p_entry.get("email") or p_entry.get("name") or "").lower().strip()
                    if pkey and pkey not in seen_part_keys:
                        seen_part_keys.add(pkey)
                        participants_ordered.append(p_entry.get("display") or p_entry.get("name") or p_entry.get("email"))

                fld = m.get("folder") or "Inbox"
                if fld not in folders_ordered:
                    folders_ordered.append(fld)

                if not m.get("is_read", True):
                    has_unread = True
                if m.get("is_deleted"):
                    has_deleted = True
                if m.get("is_draft"):
                    has_draft = True
                if m.get("importance") == "High":
                    highest_imp = "High"
                elif m.get("importance") == "Low" and highest_imp == "Normal":
                    highest_imp = "Low"

                # Update folder stats
                self.folder_stats[fld]["total"] += 1
                if not m.get("is_read", True):
                    self.folder_stats[fld]["unread"] += 1

            # Primary folder for the chain (prefer Inbox if any message is in Inbox, else first non-Sent folder or first folder)
            if "Inbox" in folders_ordered:
                primary_folder = "Inbox"
            elif any(f not in ("Sent Items", "Deleted Items") for f in folders_ordered):
                primary_folder = next(f for f in folders_ordered if f not in ("Sent Items", "Deleted Items"))
            else:
                primary_folder = folders_ordered[0] if folders_ordered else "Inbox"

            for fld in folders_ordered:
                self.folder_stats[fld]["chains"] += 1

            first_m = msgs[0]
            last_m = msgs[-1]
            snippet_raw = last_m.get("body_plain") or html_to_plain_text(last_m.get("body_html", ""))
            snippet = re.sub(r'\s+', ' ', snippet_raw).strip()[:160]

            chain_obj = {
                "chain_id": chain_id,
                "subject": chain_subject,
                "msg_count": len(msgs),
                "attachment_count": len(chain_attachments),
                "attachments": chain_attachments,
                "participants": participants_ordered,
                "senders": senders_ordered,
                "folders": folders_ordered,
                "primary_folder": primary_folder,
                "first_time_utc": first_m.get("time_utc", ""),
                "first_time_local": first_m.get("time_local", ""),
                "last_time_utc": last_m.get("time_utc", ""),
                "last_time_local": last_m.get("time_local", ""),
                "last_time_sort": last_m.get("time_sort", ""),
                "has_unread": has_unread,
                "has_deleted": has_deleted,
                "has_draft": has_draft,
                "importance": highest_imp,
                "last_snippet": snippet,
                "messages": msgs
            }
            self.mail_chains.append(chain_obj)

        # Sort mail chains with most recent activity first
        self.mail_chains.sort(key=lambda c: c.get("last_time_sort") or "", reverse=True)
        self.mail_chains_map = {c["chain_id"]: c for c in self.mail_chains}
        log_progress(f"  Reconstructed {len(self.mail_chains)} Mail Chains across {len(self.all_messages_list)} messages.")

    def process_calendar_meetings(self):
        self.clean_meetings = []
        seen_meetings = set()
        for m in self.calendar_raw:
            if not isinstance(m, dict):
                continue
            start_raw = m.get("Start") or m.get("start") or m.get("StartTime") or m.get("startTime") or m.get("StartDate") or ""
            if isinstance(start_raw, dict):
                start_raw = start_raw.get("DateTime") or start_raw.get("dateTime") or start_raw.get("Value") or ""
            end_raw = m.get("End") or m.get("end") or m.get("EndTime") or m.get("endTime") or m.get("EndDate") or ""
            if isinstance(end_raw, dict):
                end_raw = end_raw.get("DateTime") or end_raw.get("dateTime") or end_raw.get("Value") or ""

            s_utc, s_local, s_sort = format_time(start_raw)
            e_utc, e_local, _ = format_time(end_raw)

            subj = decode_mime_words(str(m.get("Subject") or m.get("subject") or "Calendar Event")).strip()
            org_raw = m.get("Organizer") or m.get("organizer") or {"name": m.get("OrganizerName") or m.get("organizerName") or "", "address": m.get("OrganizerAddress") or m.get("organizerAddress") or ""}
            org_list = parse_email_address_list(org_raw)
            org_name = org_list[0]["name"] if org_list else str(m.get("OrganizerName") or "")
            org_email = org_list[0]["email"] if org_list else str(m.get("OrganizerAddress") or "")

            loc_raw = m.get("Location") or m.get("location") or ""
            if isinstance(loc_raw, dict):
                loc_raw = loc_raw.get("DisplayName") or loc_raw.get("displayName") or ""
            loc = decode_mime_words(str(loc_raw)).strip()

            att_raw = m.get("Attendees") or m.get("attendees") or m.get("RequiredAttendees") or m.get("requiredAttendees") or []
            att_list = parse_email_address_list(att_raw)
            attendees_str = "; ".join(a["display"] for a in att_list) if att_list else ("; ".join(str(x) for x in att_raw) if isinstance(att_raw, list) else str(att_raw or ""))

            join_url = str(m.get("OnlineMeetingUrl") or m.get("onlineMeetingUrl") or m.get("JoinUrl") or m.get("joinUrl") or m.get("shortOnlineMeetingJoinUrl") or "").strip()
            _, body_plain = self.extract_body_fields(m)

            m_key = (subj.lower(), s_local, org_email.lower())
            if m_key in seen_meetings:
                continue
            seen_meetings.add(m_key)
            self.clean_meetings.append({
                "subject": subj,
                "organizer": org_name,
                "organizerEmail": org_email,
                "attendees": attendees_str,
                "startTime": s_local,
                "startTimeUtc": s_utc,
                "endTime": e_local,
                "endTimeUtc": e_utc,
                "location": loc or "Outlook Calendar",
                "joinUrl": join_url,
                "body": body_plain[:1000],
                "source": str(m.get("_source_file") or "Outlook Calendar"),
                "_sort": s_sort
            })
        self.clean_meetings.sort(key=lambda x: x.get("_sort") or "", reverse=True)
        for cm in self.clean_meetings:
            cm.pop("_sort", None)

    def generate_outputs(self):
        # 1. Mail Chains Summary CSV
        with open(os.path.join(self.output_dir, "Outlook_Mail_Chains_Summary.csv"), "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "chain_id", "subject", "primary_folder", "folders", "msg_count", "attachment_count",
                "first_time_local", "first_time_utc", "last_time_local", "last_time_utc",
                "senders", "participants", "importance", "has_unread", "has_deleted", "last_snippet"
            ])
            writer.writeheader()
            for c in self.mail_chains:
                writer.writerow({
                    "chain_id": c["chain_id"],
                    "subject": c["subject"],
                    "primary_folder": c["primary_folder"],
                    "folders": "; ".join(c["folders"]),
                    "msg_count": c["msg_count"],
                    "attachment_count": c["attachment_count"],
                    "first_time_local": c["first_time_local"],
                    "first_time_utc": c["first_time_utc"],
                    "last_time_local": c["last_time_local"],
                    "last_time_utc": c["last_time_utc"],
                    "senders": "; ".join(c["senders"]),
                    "participants": "; ".join(c["participants"]),
                    "importance": c["importance"],
                    "has_unread": "Yes" if c["has_unread"] else "No",
                    "has_deleted": "Yes" if c["has_deleted"] else "No",
                    "last_snippet": c["last_snippet"]
                })

        # 2. Complete Email Messages CSV
        with open(os.path.join(self.output_dir, "Outlook_Messages_Complete.csv"), "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "chain_id", "chain_index", "reply_depth", "parent_msg_id", "id", "internet_message_id",
                "in_reply_to", "references", "conversation_index", "folder", "subject",
                "sender_name", "sender_email", "to_recipients", "cc_recipients", "bcc_recipients",
                "time_local", "time_utc", "importance", "sensitivity", "is_read", "is_draft", "is_deleted",
                "attachment_count", "attachments_names", "body_plain", "body_html", "transport_headers", "source_file"
            ])
            writer.writeheader()
            for c in self.mail_chains:
                for m in c["messages"]:
                    writer.writerow({
                        "chain_id": c["chain_id"],
                        "chain_index": m.get("chain_index", 1),
                        "reply_depth": m.get("reply_depth", 0),
                        "parent_msg_id": m.get("parent_msg_id", ""),
                        "id": m["id"],
                        "internet_message_id": m.get("internet_message_id", ""),
                        "in_reply_to": m.get("in_reply_to", ""),
                        "references": m.get("references", ""),
                        "conversation_index": m.get("conversation_index", ""),
                        "folder": m.get("folder", "Inbox"),
                        "subject": m.get("subject", ""),
                        "sender_name": m.get("sender_name", ""),
                        "sender_email": m.get("sender_email", ""),
                        "to_recipients": "; ".join(r.get("display", "") for r in m.get("to_recipients", [])),
                        "cc_recipients": "; ".join(r.get("display", "") for r in m.get("cc_recipients", [])),
                        "bcc_recipients": "; ".join(r.get("display", "") for r in m.get("bcc_recipients", [])),
                        "time_local": m.get("time_local", ""),
                        "time_utc": m.get("time_utc", ""),
                        "importance": m.get("importance", "Normal"),
                        "sensitivity": m.get("sensitivity", "Normal"),
                        "is_read": "Yes" if m.get("is_read", True) else "No",
                        "is_draft": "Yes" if m.get("is_draft") else "No",
                        "is_deleted": "Yes" if m.get("is_deleted") else "No",
                        "attachment_count": len(m.get("attachments", [])),
                        "attachments_names": "; ".join(a.get("fileName", "") for a in m.get("attachments", [])),
                        "body_plain": m.get("body_plain", ""),
                        "body_html": m.get("body_html", ""),
                        "transport_headers": m.get("transport_headers", ""),
                        "source_file": m.get("source_file", "")
                    })

        # 3. Attachments Catalog CSV
        with open(os.path.join(self.output_dir, "Outlook_Attachments_Catalog.csv"), "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "att_id", "fileName", "savedName", "category", "contentType", "size", "sha256",
                "isInline", "contentId", "extracted", "rel_path", "chain_id", "msg_id",
                "subject", "sender", "time_local", "folder", "source_file"
            ])
            writer.writeheader()
            for att in self.attachments_catalog:
                writer.writerow(att)

        # 4. Calendar Meetings CSV
        with open(os.path.join(self.output_dir, "Outlook_Calendar_Meetings.csv"), "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "subject", "organizer", "organizerEmail", "attendees", "startTime", "startTimeUtc",
                "endTime", "endTimeUtc", "location", "joinUrl", "body", "source"
            ])
            writer.writeheader()
            for cm in self.clean_meetings:
                writer.writerow(cm)

        # 5. Contacts Directory CSV
        unique_contacts = []
        seen_c_keys = set()
        for c in self.contacts_dict.values():
            ck = (c.get("email") or c.get("name") or "").lower().strip()
            if ck and ck not in seen_c_keys:
                seen_c_keys.add(ck)
                unique_contacts.append(c)
        unique_contacts.sort(key=lambda x: (-(x.get("sent_count", 0) + x.get("received_count", 0)), x.get("name", "").lower()))
        self.clean_contacts = unique_contacts

        with open(os.path.join(self.output_dir, "Outlook_Contacts_Directory.csv"), "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "name", "email", "role", "department", "company", "phone", "sent_count", "received_count", "persona_id", "source"
            ])
            writer.writeheader()
            for ct in unique_contacts:
                writer.writerow(ct)

        # 6. LevelDB & Olk Forensic Records CSV
        with open(os.path.join(self.output_dir, "Outlook_LevelDB_Forensic_Records.csv"), "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "source_file", "table_name", "seq", "record_type", "key", "value", "timestamp"
            ])
            writer.writeheader()
            for lrec in self.leveldb_records:
                writer.writerow(lrec)

        # 7. Prepare Folder Summary List
        standard_order = ["Inbox", "Sent Items", "Drafts", "Deleted Items", "Archive", "Junk Email", "Outbox", "[Recovered Orphan Items]"]
        folders_summary = []
        seen_fnames = set()
        for sf in standard_order:
            if sf in self.folder_stats or sf in ("Inbox", "Sent Items", "Drafts", "Deleted Items"):
                st = self.folder_stats.get(sf, {"total": 0, "unread": 0, "chains": 0})
                folders_summary.append({
                    "name": sf,
                    "total_messages": st["total"],
                    "unread_messages": st["unread"],
                    "total_chains": st["chains"]
                })
                seen_fnames.add(sf)
        for fn, st in sorted(self.folder_stats.items()):
            if fn not in seen_fnames:
                folders_summary.append({
                    "name": fn,
                    "total_messages": st["total"],
                    "unread_messages": st["unread"],
                    "total_chains": st["chains"]
                })

        # 8. Build Embedded Forensic Dataset for Standalone Outlook UI Viewer
        export_data = {
            "stats": {
                "case_name": self.case_name,
                "case_dir": self.case_dir,
                "target_path": self.target_path,
                "user": self.primary_user,
                "email": self.primary_email,
                "tenant": self.primary_tenant,
                "account_identities": self.account_identities,
                "total_mail_chains": len(self.mail_chains),
                "total_messages": len(self.all_messages_list),
                "total_attachments": len(self.attachments_catalog),
                "total_meetings": len(self.clean_meetings),
                "total_contacts": len(unique_contacts),
                "total_folders": len(folders_summary),
                "total_leveldb_records": len(self.leveldb_records),
                "generated_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            },
            "folders": folders_summary,
            "mail_chains": self.mail_chains,
            "attachments": self.attachments_catalog,
            "meetings": self.clean_meetings,
            "contacts": unique_contacts,
            "leveldb_records": self.leveldb_records[:1500]
        }
        parsing_status["stats"] = export_data["stats"]

        embedded_json = json.dumps(
            export_data,
            default=lambda o: None if getattr(o, "__class__", None) and o.__class__.__name__ in ("Undefined", "Null") else str(o),
            ensure_ascii=False
        )
        # Escape '</script>' inside JSON string payloads so it never prematurely closes the HTML <script> tag
        embedded_json_safe = embedded_json.replace("</script>", "<\\/script>").replace("</SCRIPT>", "<\\/SCRIPT>")

        viewer_html = VIEWER_TEMPLATE_HTML.replace(
            "/*__OUTLOOK_FORENSIC_DATA_PLACEHOLDER__*/",
            f"window.OUTLOOK_FORENSIC_DATA = {embedded_json_safe};"
        )
        viewer_dest = os.path.join(self.case_dir, "Outlook_Forensic_Viewer.html")
        with open(viewer_dest, "w", encoding="utf-8") as f:
            f.write(viewer_html)

        # 9. Generate Case Audit Report Text
        audit_txt = f"""MICROSOFT OUTLOOK FORENSIC CASE REPORT
======================================
Case Reference   : {self.case_name}
Custodian Name   : {export_data['stats']['user']}
Custodian Email  : {export_data['stats']['email'] or 'N/A'}
Tenant / Domain  : {export_data['stats']['tenant']}
Evidence Source  : {self.target_path}
Generated Date   : {export_data['stats']['generated_at']}
Case Directory   : {self.case_dir}

FORENSIC EVIDENCE INVENTORY:
----------------------------
• Reconstructed Mail Chains : {export_data['stats']['total_mail_chains']:,}
• Total Email Messages      : {export_data['stats']['total_messages']:,}
• Extracted Attachments     : {export_data['stats']['total_attachments']:,}
• Mailbox Folders           : {export_data['stats']['total_folders']:,}
• Calendar Meetings         : {export_data['stats']['total_meetings']:,}
• Contacts & Correspondents : {export_data['stats']['total_contacts']:,}
• LevelDB / Olk Records     : {export_data['stats']['total_leveldb_records']:,}

CASE FOLDER CONTENTS:
---------------------
1. Outlook_Forensic_Viewer.html          - Standalone Interactive Outlook 365 Forensic UI (Embedded Dataset)
2. Outlook_Mail_Chains_Summary.csv       - Reconstructed Conversation Mail Chains & Thread Metadata
3. Outlook_Messages_Complete.csv         - Full Email Records (Headers, HTML/Plain Bodies, MAPI & Thread Links)
4. Outlook_Attachments_Catalog.csv       - Complete Attachment Manifest with SHA-256 Hashes & Sizes
5. Outlook_Calendar_Meetings.csv         - Extracted Calendar Appointments & Meeting Invites
6. Outlook_Contacts_Directory.csv        - Address Book Contacts & Correlated Email Participants
7. Outlook_LevelDB_Forensic_Records.csv  - Raw Decoded LevelDB / IndexedDB / Olk LocalStorage Records
8. outlook_attachments/                  - Unaltered Extracted Binary Attachments & Inline CID Media

This case folder is completely standalone and portable.
Double-click Outlook_Forensic_Viewer.html to inspect all mail chains, headers, and attachments offline!
"""
        with open(os.path.join(self.case_dir, "Case_Audit_Summary.txt"), "w", encoding="utf-8") as f:
            f.write(audit_txt)

        parsing_status["active_case"] = self.case_name
        parsing_status["case_dir"] = self.case_dir
        parsing_status["stats"] = export_data["stats"]


VIEWER_TEMPLATE_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Microsoft Outlook Forensic Viewer</title>
<style>
:root {
  --primary: #0f6cbd;
  --primary-hover: #115ea3;
  --primary-light: #ebf3fc;
  --primary-border: #b4d6fa;
  --bg-app: #f5f5f5;
  --bg-sidebar: #fafafa;
  --bg-folders: #f0f2f5;
  --bg-nav: #0a2e4a;
  --bg-card: #ffffff;
  --bg-chain-head: #f8fafd;
  --bg-msg-head: #f9fbfd;
  --text-main: #242424;
  --text-muted: #5c5c5c;
  --text-light: #8a8a8a;
  --border: #e0e0e0;
  --shadow: 0 1px 3px rgba(0,0,0,0.08);
  --shadow-lg: 0 4px 14px rgba(0,0,0,0.12);
  --danger: #d13438;
  --success: #107c41;
  --warning: #d97706;
}

[data-theme="dark"] {
  --primary: #479ef5;
  --primary-hover: #62abf5;
  --primary-light: #1b2e42;
  --primary-border: #284b70;
  --bg-app: #141418;
  --bg-sidebar: #1b1b22;
  --bg-folders: #17171d;
  --bg-nav: #071929;
  --bg-card: #202028;
  --bg-chain-head: #252834;
  --bg-msg-head: #242631;
  --text-main: #f0f0f5;
  --text-muted: #a6a6b8;
  --text-light: #75758a;
  --border: #30303e;
  --shadow: 0 1px 4px rgba(0,0,0,0.35);
  --shadow-lg: 0 6px 18px rgba(0,0,0,0.5);
}

* { box-sizing: border-box; margin: 0; padding: 0; font-family: "Segoe UI", -apple-system, BlinkMacSystemFont, Roboto, sans-serif; }
body { height: 100vh; display: flex; flex-direction: column; background: var(--bg-app); color: var(--text-main); overflow: hidden; }

/* Top Outlook Ribbon Header */
.app-header {
  height: 52px;
  background: var(--bg-nav);
  color: white;
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 16px;
  border-bottom: 1px solid rgba(255,255,255,0.12);
  flex-shrink: 0;
  gap: 12px;
}
.app-logo { display: flex; align-items: center; gap: 10px; font-weight: 600; font-size: 15px; letter-spacing: 0.2px; white-space: nowrap; }
.app-logo svg { width: 24px; height: 24px; fill: #479ef5; flex-shrink: 0; }
.user-tag { background: rgba(255,255,255,0.14); padding: 3px 10px; border-radius: 12px; font-size: 11.5px; white-space: nowrap; border: 1px solid rgba(255,255,255,0.12); }

/* Global Search Bar */
.header-search-wrapper { flex: 1; max-width: 480px; margin: 0 10px; }
.header-search-box {
  display: flex;
  align-items: center;
  background: rgba(255, 255, 255, 0.14);
  border: 1px solid rgba(255, 255, 255, 0.24);
  border-radius: 6px;
  padding: 5px 12px;
  gap: 8px;
  transition: all 0.2s;
}
.header-search-box:focus-within {
  background: rgba(255, 255, 255, 0.22);
  border-color: #62abf5;
  box-shadow: 0 0 0 2px rgba(71, 158, 245, 0.35);
}
.global-search-input {
  flex: 1;
  background: transparent;
  border: none;
  outline: none;
  color: #fff;
  font-size: 13px;
  width: 100%;
}
.global-search-input::placeholder { color: rgba(255, 255, 255, 0.7); font-size: 12.5px; }
.btn-clear-search { background: none; border: none; color: rgba(255,255,255,0.7); cursor: pointer; font-size: 13px; padding: 0 4px; }
.btn-clear-search:hover { color: #fff; }
.btn-search-toggle {
  background: transparent;
  border: 1px solid rgba(255,255,255,0.28);
  color: #fff;
  font-size: 11px;
  font-weight: 700;
  border-radius: 4px;
  padding: 2px 7px;
  cursor: pointer;
}
.btn-search-toggle.active { background: #ffb300; color: #000; border-color: #ffb300; }

.header-actions { display: flex; align-items: center; gap: 8px; white-space: nowrap; }
.btn-icon {
  background: rgba(255,255,255,0.08);
  border: 1px solid rgba(255,255,255,0.14);
  color: white;
  cursor: pointer;
  padding: 6px 11px;
  border-radius: 5px;
  font-size: 12px;
  display: inline-flex;
  align-items: center;
  gap: 6px;
  text-decoration: none;
  transition: background 0.15s;
}
.btn-icon:hover { background: rgba(255,255,255,0.18); }
.btn-accent { background: #0f6cbd !important; border-color: #3b8fd9 !important; font-weight: 600; }
.btn-accent:hover { background: #115ea3 !important; }

/* Main Container */
.app-container { display: flex; flex: 1; height: calc(100vh - 52px); overflow: hidden; }

/* Left Navigation Rail */
.nav-rail {
  width: 68px;
  background: var(--bg-nav);
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: 10px 0;
  gap: 6px;
  flex-shrink: 0;
}
.nav-tab {
  width: 58px;
  height: 52px;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 3px;
  color: #a8c1d8;
  cursor: pointer;
  border-radius: 6px;
  font-size: 10.5px;
  transition: all 0.15s;
  user-select: none;
  position: relative;
}
.nav-tab:hover { color: #fff; background: rgba(255,255,255,0.08); }
.nav-tab.active {
  color: #fff;
  background: rgba(255,255,255,0.15);
  border-left: 3px solid #479ef5;
  border-radius: 0 6px 6px 0;
  font-weight: 600;
}
.nav-tab .icon { font-size: 18px; }

/* Pane 1: Mail Folders Sidebar */
.folders-pane {
  width: 225px;
  background: var(--bg-folders);
  border-right: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  flex-shrink: 0;
  user-select: none;
}
.folders-section-title {
  padding: 14px 14px 6px;
  font-size: 11px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.6px;
  color: var(--text-muted);
}
.folders-list { flex: 1; overflow-y: auto; padding: 4px 8px; display: flex; flex-direction: column; gap: 2px; }
.folder-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 8px 10px;
  border-radius: 6px;
  cursor: pointer;
  font-size: 13px;
  color: var(--text-main);
  transition: background 0.12s;
}
.folder-item:hover { background: rgba(0,0,0,0.05); }
[data-theme="dark"] .folder-item:hover { background: rgba(255,255,255,0.06); }
.folder-item.active {
  background: var(--primary-light);
  color: var(--primary);
  font-weight: 600;
}
.folder-name-wrap { display: flex; align-items: center; gap: 8px; min-width: 0; }
.folder-name-text { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.folder-count-badge {
  font-size: 11px;
  font-weight: 600;
  color: var(--text-muted);
  background: rgba(0,0,0,0.06);
  padding: 1px 7px;
  border-radius: 10px;
}
[data-theme="dark"] .folder-count-badge { background: rgba(255,255,255,0.08); }
.folder-item.active .folder-count-badge { background: var(--primary); color: #fff; }

/* Pane 2: Mail Chains List Sidebar */
.chains-pane {
  width: 355px;
  background: var(--bg-sidebar);
  border-right: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  flex-shrink: 0;
}
.chains-pane-header {
  padding: 12px 14px;
  border-bottom: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.chains-title-row { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
.chains-pane-title { font-size: 15px; font-weight: 700; color: var(--text-main); }
.view-mode-switch {
  display: inline-flex;
  background: var(--bg-app);
  border: 1px solid var(--border);
  border-radius: 6px;
  overflow: hidden;
}
.view-mode-btn {
  padding: 4px 9px;
  font-size: 11px;
  font-weight: 600;
  border: none;
  background: transparent;
  color: var(--text-muted);
  cursor: pointer;
}
.view-mode-btn.active { background: var(--primary); color: #fff; }

.search-box {
  width: 100%;
  padding: 7px 11px;
  border: 1px solid var(--border);
  border-radius: 6px;
  background: var(--bg-card);
  color: var(--text-main);
  font-size: 12.5px;
  outline: none;
}
.search-box:focus { border-color: var(--primary); }

.filter-pills-row { display: flex; gap: 5px; overflow-x: auto; padding-bottom: 2px; }
.filter-pill {
  padding: 3px 9px;
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 12px;
  font-size: 11px;
  cursor: pointer;
  white-space: nowrap;
  color: var(--text-muted);
  user-select: none;
}
.filter-pill.active { background: var(--primary); color: white; border-color: var(--primary); font-weight: 600; }

.chains-list { flex: 1; overflow-y: auto; }
.chain-list-item {
  display: flex;
  gap: 11px;
  padding: 11px 14px;
  cursor: pointer;
  border-bottom: 1px solid var(--border);
  border-left: 3px solid transparent;
  transition: background 0.12s;
  position: relative;
}
.chain-list-item:hover { background: rgba(15, 108, 189, 0.05); }
.chain-list-item.active {
  background: var(--primary-light);
  border-left-color: var(--primary);
}
.chain-list-item.unread .chain-item-subject { font-weight: 700; color: var(--primary); }

.chain-avatar {
  width: 38px;
  height: 38px;
  border-radius: 50%;
  background: #0f6cbd;
  color: white;
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: 600;
  font-size: 13px;
  flex-shrink: 0;
  position: relative;
  margin-top: 2px;
}
.chain-count-pill {
  position: absolute;
  bottom: -4px;
  right: -5px;
  background: #0a2e4a;
  color: #fff;
  border-radius: 10px;
  font-size: 9.5px;
  padding: 1px 5px;
  font-weight: 700;
  border: 1.5px solid var(--bg-sidebar);
}
.chain-item-body { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 3px; }
.chain-item-top { display: flex; justify-content: space-between; align-items: baseline; gap: 6px; }
.chain-item-senders { font-size: 13px; font-weight: 600; color: var(--text-main); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.chain-item-time { font-size: 11px; color: var(--text-light); white-space: nowrap; flex-shrink: 0; }
.chain-item-subject { font-size: 12.5px; font-weight: 600; color: var(--text-main); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.chain-item-snippet { font-size: 11.5px; color: var(--text-muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.chain-item-badges { display: flex; align-items: center; gap: 5px; flex-wrap: wrap; margin-top: 2px; }
.mini-badge {
  font-size: 10px;
  padding: 1px 6px;
  border-radius: 4px;
  font-weight: 600;
  background: rgba(0,0,0,0.06);
  color: var(--text-muted);
}
[data-theme="dark"] .mini-badge { background: rgba(255,255,255,0.08); }
.mini-badge.att { background: #e0f2fe; color: #0369a1; }
[data-theme="dark"] .mini-badge.att { background: #0c4a6e; color: #7dd3fc; }
.mini-badge.chain { background: #ede9fe; color: #6d28d9; }
[data-theme="dark"] .mini-badge.chain { background: #3b0764; color: #d8b4fe; }
.mini-badge.high { background: #fee2e2; color: #b91c1c; }
.mini-badge.deleted { background: #fef3c7; color: #b45309; }

/* Pane 3: Mail Chain Reading Pane */
.reading-pane {
  flex: 1;
  display: flex;
  flex-direction: column;
  background: var(--bg-app);
  overflow: hidden;
}
.chain-header-bar {
  background: var(--bg-card);
  border-bottom: 1px solid var(--border);
  padding: 14px 22px;
  display: flex;
  flex-direction: column;
  gap: 10px;
  flex-shrink: 0;
  box-shadow: var(--shadow);
  z-index: 2;
}
.chain-header-top { display: flex; justify-content: space-between; align-items: flex-start; gap: 14px; flex-wrap: wrap; }
.chain-subject-title { font-size: 17px; font-weight: 700; color: var(--text-main); line-height: 1.3; word-break: break-word; }
.chain-meta-sub { font-size: 12px; color: var(--text-muted); display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-top: 4px; }
.chain-actions-group { display: flex; align-items: center; gap: 7px; flex-shrink: 0; flex-wrap: wrap; }
.btn-pane-action {
  padding: 6px 11px;
  border: 1px solid var(--border);
  background: var(--bg-app);
  color: var(--text-main);
  border-radius: 6px;
  cursor: pointer;
  font-size: 12px;
  font-weight: 600;
  display: inline-flex;
  align-items: center;
  gap: 5px;
  text-decoration: none;
  transition: all 0.15s;
}
.btn-pane-action:hover { border-color: var(--primary); color: var(--primary); }
.btn-pane-action.primary { background: var(--primary); color: #fff; border-color: var(--primary); }
.btn-pane-action.primary:hover { background: var(--primary-hover); color: #fff; }

/* Chain-Level Attachments Strip */
.chain-attachments-strip {
  display: flex;
  align-items: center;
  gap: 8px;
  overflow-x: auto;
  padding: 8px 12px;
  background: var(--bg-chain-head);
  border: 1px solid var(--primary-border);
  border-radius: 6px;
}
.chain-att-chip {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  padding: 5px 10px;
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 6px;
  font-size: 12px;
  cursor: pointer;
  white-space: nowrap;
  transition: all 0.15s;
}
.chain-att-chip:hover { border-color: var(--primary); box-shadow: var(--shadow); }

/* Mail Chain Messages Scroll Container */
.chain-messages-scroll {
  flex: 1;
  overflow-y: auto;
  padding: 18px 24px 36px;
  display: flex;
  flex-direction: column;
  gap: 16px;
}

/* Individual Email Card in a Mail Chain */
.email-chain-node {
  position: relative;
  display: flex;
  flex-direction: column;
}
.email-chain-connector {
  position: absolute;
  top: -16px;
  left: 24px;
  width: 2px;
  height: 16px;
  background: var(--primary);
  opacity: 0.45;
}
.email-card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 8px;
  box-shadow: var(--shadow);
  overflow: hidden;
  transition: border-color 0.2s, box-shadow 0.2s;
}
.email-card.highlight-target {
  border-color: var(--primary);
  box-shadow: 0 0 0 3px rgba(15, 108, 189, 0.25);
}
.email-card-header {
  padding: 13px 18px;
  background: var(--bg-msg-head);
  border-bottom: 1px solid var(--border);
  cursor: pointer;
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.email-card-top-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
  flex-wrap: wrap;
}
.email-sender-box { display: flex; align-items: center; gap: 11px; min-width: 0; }
.email-sender-avatar {
  width: 36px;
  height: 36px;
  border-radius: 50%;
  background: #0f6cbd;
  color: #fff;
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: 700;
  font-size: 13px;
  flex-shrink: 0;
}
.email-sender-details { display: flex; flex-direction: column; min-width: 0; }
.email-sender-title { font-size: 14px; font-weight: 700; color: var(--text-main); display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.email-sender-addr { font-size: 12px; color: var(--text-muted); font-weight: 400; }
.email-step-badge {
  font-size: 11px;
  padding: 2px 8px;
  border-radius: 12px;
  background: var(--primary-light);
  color: var(--primary);
  font-weight: 700;
  border: 1px solid var(--primary-border);
}
.email-timestamps-box {
  text-align: right;
  font-size: 11.5px;
  color: var(--text-muted);
  display: flex;
  flex-direction: column;
  align-items: flex-end;
  gap: 2px;
}

/* Complete Envelope Recipients Grid (From, To, Cc, Bcc, Message-ID) */
.email-envelope-grid {
  display: grid;
  grid-template-columns: 78px 1fr;
  row-gap: 4px;
  column-gap: 8px;
  font-size: 12px;
  padding-top: 6px;
  border-top: 1px dashed var(--border);
}
.env-label { font-weight: 700; color: var(--text-muted); text-align: right; }
.env-val { color: var(--text-main); word-break: break-word; }
.recip-pill {
  display: inline-block;
  background: var(--bg-app);
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: 1px 7px;
  margin: 1px 4px 1px 0;
  font-size: 11.5px;
}
.recip-pill.bcc { background: #fef3c7; border-color: #f59e0b; color: #92400e; }
[data-theme="dark"] .recip-pill.bcc { background: #451a03; border-color: #d97706; color: #fde68a; }

/* Message Body Tabs (Rich HTML | Plain Text | Forensic Headers & MAPI) */
.email-view-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 6px 18px;
  background: var(--bg-app);
  border-bottom: 1px solid var(--border);
  gap: 10px;
  flex-wrap: wrap;
}
.body-mode-tabs { display: flex; gap: 6px; }
.body-tab-btn {
  padding: 4px 11px;
  font-size: 11.5px;
  font-weight: 600;
  border: 1px solid var(--border);
  background: var(--bg-card);
  color: var(--text-muted);
  border-radius: 5px;
  cursor: pointer;
}
.body-tab-btn.active {
  background: var(--primary);
  color: #fff;
  border-color: var(--primary);
}

/* Attachments Grid inside Message Card */
.msg-attachments-bar {
  padding: 12px 18px;
  background: var(--bg-chain-head);
  border-bottom: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.msg-att-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(255px, 1fr));
  gap: 10px;
}
.att-card {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 9px 12px;
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 7px;
  box-shadow: var(--shadow);
  transition: border-color 0.15s;
}
.att-card:hover { border-color: var(--primary); }
.att-icon-thumb {
  width: 42px;
  height: 42px;
  border-radius: 6px;
  background: var(--bg-app);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 22px;
  flex-shrink: 0;
  overflow: hidden;
  border: 1px solid var(--border);
}
.att-icon-thumb img { width: 100%; height: 100%; object-fit: cover; }
.att-meta { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 2px; }
.att-filename { font-size: 12.5px; font-weight: 700; color: var(--text-main); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.att-subinfo { font-size: 10.5px; color: var(--text-muted); display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
.att-actions { display: flex; flex-direction: column; gap: 4px; flex-shrink: 0; }
.btn-att {
  padding: 3px 8px;
  font-size: 11px;
  font-weight: 600;
  border-radius: 4px;
  border: 1px solid var(--border);
  background: var(--bg-app);
  color: var(--text-main);
  cursor: pointer;
  text-decoration: none;
  text-align: center;
}
.btn-att:hover { background: var(--primary); color: #fff; border-color: var(--primary); }

/* Email Body Content Container */
.email-body-container {
  padding: 18px 22px;
  font-size: 14px;
  line-height: 1.6;
  color: var(--text-main);
  overflow-x: auto;
  word-break: break-word;
}
.email-render-scope img { max-width: 100%; height: auto; border-radius: 4px; }
.email-render-scope table { border-collapse: collapse; max-width: 100%; }
.email-render-scope blockquote {
  border-left: 3px solid var(--primary);
  padding-left: 12px;
  margin: 8px 0;
  color: var(--text-muted);
}
.plain-text-box {
  white-space: pre-wrap;
  font-family: Consolas, "SFMono-Regular", Menlo, monospace;
  font-size: 13px;
  line-height: 1.55;
  background: var(--bg-app);
  padding: 14px;
  border-radius: 6px;
  border: 1px solid var(--border);
}
.headers-forensic-box {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

/* Keyword Highlighting */
mark.kw-highlight {
  background: #ffeb3b;
  color: #111;
  padding: 1px 4px;
  border-radius: 3px;
  font-weight: 700;
}

/* Full-Page Table Views (Search, Attachments, Calendar, Contacts, LevelDB, Overview) */
.table-view-container {
  flex: 1;
  padding: 22px 26px;
  overflow-y: auto;
  display: flex;
  flex-direction: column;
  gap: 16px;
}
.view-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 12px;
}
.view-header h2 { font-size: 20px; font-weight: 700; }
.search-filter-box {
  padding: 8px 14px;
  border: 1px solid var(--border);
  border-radius: 6px;
  background: var(--bg-card);
  color: var(--text-main);
  width: 300px;
  font-size: 13px;
}

.stats-cards-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
  gap: 12px;
}
.stat-card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  padding: 16px;
  border-radius: 8px;
  box-shadow: var(--shadow);
}
.stat-val { font-size: 24px; font-weight: 700; color: var(--primary); }
.stat-label { font-size: 12px; color: var(--text-muted); margin-top: 4px; }

.data-table-wrapper {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 8px;
  overflow: auto;
  box-shadow: var(--shadow);
}
table.forensic-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
  text-align: left;
}
table.forensic-table th {
  background: var(--bg-sidebar);
  padding: 10px 14px;
  font-weight: 600;
  border-bottom: 1px solid var(--border);
  color: var(--text-muted);
  position: sticky;
  top: 0;
}
table.forensic-table td {
  padding: 10px 14px;
  border-bottom: 1px solid var(--border);
  vertical-align: top;
}
table.forensic-table tr:hover { background: rgba(15, 108, 189, 0.04); }

/* Search & Distinct Words Panel */
.words-panel {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 14px 18px;
  box-shadow: var(--shadow);
}
.words-cloud {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  max-height: 170px;
  overflow-y: auto;
  margin-top: 10px;
}
.word-pill {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 4px 10px;
  border-radius: 6px;
  font-family: Consolas, monospace;
  font-size: 12px;
  font-weight: 600;
  background: var(--bg-app);
  border: 1px solid var(--border);
  color: var(--text-main);
  cursor: pointer;
}
.word-pill:hover, .word-pill.active {
  background: var(--primary);
  color: #fff;
  border-color: var(--primary);
}
.search-result-card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 14px 18px;
  box-shadow: var(--shadow);
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.search-result-card:hover { border-color: var(--primary); }

/* Empty Placeholder */
.empty-placeholder {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  height: 100%;
  color: var(--text-muted);
  gap: 10px;
  padding: 40px;
  text-align: center;
}
.empty-placeholder .icon { font-size: 46px; opacity: 0.55; }

/* Attachment & Image Preview Modal */
.modal-overlay {
  position: fixed;
  top: 0; left: 0; right: 0; bottom: 0;
  background: rgba(0,0,0,0.75);
  display: none;
  align-items: center;
  justify-content: center;
  z-index: 2000;
  padding: 20px;
}
.modal-overlay.active { display: flex; }
.modal-card {
  background: var(--bg-card);
  border-radius: 10px;
  max-width: 960px;
  width: 95%;
  max-height: 90vh;
  display: flex;
  flex-direction: column;
  overflow: hidden;
  box-shadow: var(--shadow-lg);
  border: 1px solid var(--border);
}
.modal-header {
  padding: 14px 20px;
  background: var(--bg-nav);
  color: #fff;
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.modal-body {
  padding: 20px;
  overflow-y: auto;
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 14px;
}
</style>
</head>
<body>

<header class="app-header">
  <div class="app-logo">
    <svg viewBox="0 0 24 24"><path d="M12 2L2 7l10 5 10-5-10-5zm0 7.5l-6-3 6-3 6 3-6 3zm0 2.5l-10-5v10l10 5 10-5V7l-10 5z"/></svg>
    <span>Microsoft Outlook Forensic Suite</span>
    <span class="user-tag" id="headerCaseBadge">Case</span>
    <span class="user-tag" id="headerUserBadge">Mailbox</span>
  </div>

  <div class="header-search-wrapper">
    <div class="header-search-box">
      <span>🔍</span>
      <input type="text" id="globalSearchInput" class="global-search-input" placeholder="Search all mail chains, subjects, bodies, headers, attachments, LevelDB..." oninput="handleGlobalSearchInput(this.value)" onkeydown="if(event.key==='Enter') runGlobalSearch(this.value)">
      <button id="btnCaseSensitive" class="btn-search-toggle" onclick="toggleCaseSensitive()" title="Match Case (Aa)">Aa</button>
      <button class="btn-clear-search" onclick="clearGlobalSearch()" title="Clear Search">✖</button>
    </div>
  </div>

  <div class="header-actions">
    <a href="/" class="btn-icon" id="btnCaseManager" style="display:none;">🏠 Case Manager</a>
    <button class="btn-icon" onclick="openCaseFolder()">📂 Case Folder</button>
    <button class="btn-icon btn-accent" onclick="switchTab('overview')">📊 Audit Overview</button>
    <button class="btn-icon" onclick="toggleTheme()" id="themeBtn" title="Toggle Dark/Light Theme">🌙</button>
  </div>
</header>

<div class="app-container">
  <!-- Left Module Rail -->
  <nav class="nav-rail">
    <div class="nav-tab active" data-tab="mail" onclick="switchTab('mail')">
      <span class="icon">📬</span>
      <span>Mail</span>
    </div>
    <div class="nav-tab" data-tab="search" onclick="switchTab('search')">
      <span class="icon">🔍</span>
      <span>Search</span>
    </div>
    <div class="nav-tab" data-tab="attachments" onclick="switchTab('attachments')">
      <span class="icon">📎</span>
      <span>Files</span>
    </div>
    <div class="nav-tab" data-tab="calendar" onclick="switchTab('calendar')">
      <span class="icon">📅</span>
      <span>Calendar</span>
    </div>
    <div class="nav-tab" data-tab="contacts" onclick="switchTab('contacts')">
      <span class="icon">👥</span>
      <span>People</span>
    </div>
    <div class="nav-tab" data-tab="leveldb" onclick="switchTab('leveldb')">
      <span class="icon">🗄️</span>
      <span>LevelDB</span>
    </div>
    <div class="nav-tab" data-tab="overview" onclick="switchTab('overview')">
      <span class="icon">📊</span>
      <span>Overview</span>
    </div>
  </nav>

  <!-- TAB 1: 3-Pane Outlook Mail & Mail Chains View -->
  <div id="view-mail" style="display:flex; flex:1; overflow:hidden;">
    <!-- Pane 1: Folders Tree -->
    <aside class="folders-pane">
      <div class="folders-section-title">Mailbox Folders</div>
      <div class="folders-list" id="foldersListContainer"></div>
    </aside>

    <!-- Pane 2: Mail Chains / Conversations List -->
    <aside class="chains-pane">
      <div class="chains-pane-header">
        <div class="chains-title-row">
          <span class="chains-pane-title" id="currentFolderLabel">All Mailboxes</span>
          <div class="view-mode-switch">
            <button class="view-mode-btn active" id="btnModeChains" onclick="setListGroupingMode('chains')" title="Group emails into clear Mail Chains">🔗 Chains</button>
            <button class="view-mode-btn" id="btnModeFlat" onclick="setListGroupingMode('flat')" title="Show individual messages">✉️ Flat</button>
          </div>
        </div>
        <input type="text" id="chainFilterInput" class="search-box" placeholder="Filter mail chains by subject, sender, content..." oninput="renderChainsList()">
        <div class="filter-pills-row">
          <span class="filter-pill active" data-filter="all" onclick="setQuickFilter('all', this)">All</span>
          <span class="filter-pill" data-filter="multi" onclick="setQuickFilter('multi', this)">🔗 Chains (2+)</span>
          <span class="filter-pill" data-filter="att" onclick="setQuickFilter('att', this)">📎 Attachments</span>
          <span class="filter-pill" data-filter="high" onclick="setQuickFilter('high', this)">❗ High Priority</span>
          <span class="filter-pill" data-filter="deleted" onclick="setQuickFilter('deleted', this)">🗑️ Deleted</span>
          <span class="filter-pill" data-filter="unread" onclick="setQuickFilter('unread', this)">✉️ Unread</span>
        </div>
      </div>
      <div class="chains-list" id="chainsListContainer"></div>
    </aside>

    <!-- Pane 3: Mail Chain Reading Stage -->
    <main class="reading-pane" id="readingPaneContainer">
      <div class="empty-placeholder">
        <div class="icon">📬</div>
        <h3>Select a Mail Chain to inspect</h3>
        <p style="font-size:13px; max-width:420px;">Choose a conversation thread from the list on the left to view the complete mail chain, headers, and extracted attachments.</p>
      </div>
    </main>
  </div>

  <!-- TAB 2: Global Search & Distinct Words View -->
  <div id="view-search" class="table-view-container" style="display:none;"></div>

  <!-- TAB 3: Attachments Center View -->
  <div id="view-attachments" class="table-view-container" style="display:none;"></div>

  <!-- TAB 4: Calendar & Meetings View -->
  <div id="view-calendar" class="table-view-container" style="display:none;"></div>

  <!-- TAB 5: Contacts / People Directory View -->
  <div id="view-contacts" class="table-view-container" style="display:none;"></div>

  <!-- TAB 6: Raw LevelDB & Olk Forensic Artifacts View -->
  <div id="view-leveldb" class="table-view-container" style="display:none;"></div>

  <!-- TAB 7: Case Overview & Forensic Audit Summary -->
  <div id="view-overview" class="table-view-container" style="display:none;"></div>
</div>

<!-- Attachment & Media Preview Modal -->
<div class="modal-overlay" id="previewModal" onclick="if(event.target===this) closePreviewModal()">
  <div class="modal-card">
    <div class="modal-header">
      <div style="font-weight:700; font-size:15px; display:flex; align-items:center; gap:8px;" id="modalTitle">📎 Attachment Preview</div>
      <button onclick="closePreviewModal()" style="background:none; border:none; color:#fff; font-size:18px; cursor:pointer;">✖</button>
    </div>
    <div class="modal-body" id="modalBodyContent"></div>
  </div>
</div>

<script>
/*__OUTLOOK_FORENSIC_DATA_PLACEHOLDER__*/
</script>
<script>
const rawData = window.OUTLOOK_FORENSIC_DATA || {
  stats: {},
  folders: [],
  mail_chains: [],
  attachments: [],
  meetings: [],
  contacts: [],
  leveldb_records: []
};

let activeTab = "mail";
let selectedFolder = "ALL";
let quickFilter = "all";
let listGroupingMode = "chains"; // 'chains' or 'flat'
let activeChainId = null;
let activeHighlightMsgId = null;
let activeSearchKeyword = "";
let searchCaseSensitive = false;
let chainSortReverse = false;
let allMessagesFlat = [];

function esc(s) {
  if (s === null || s === undefined) return "";
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function formatBytes(bytes) {
  const b = Number(bytes) || 0;
  if (b === 0) return "0 B";
  if (b < 1024) return b + " B";
  if (b < 1024 * 1024) return (b / 1024).toFixed(1) + " KB";
  return (b / (1024 * 1024)).toFixed(2) + " MB";
}

function getInitials(name) {
  const clean = String(name || "U").replace(/<[^>]+>/g, "").replace(/[^a-zA-Z0-9 ]/g, " ").trim();
  if (!clean) return "U";
  const parts = clean.split(/\s+/);
  if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase();
  return clean.slice(0, 2).toUpperCase();
}

function getAvatarColor(str) {
  const palette = ["#0f6cbd", "#038387", "#8764b8", "#107c41", "#c239b3", "#d13438", "#ca5010", "#4f6bed"];
  let hash = 0;
  const s = String(str || "");
  for (let i = 0; i < s.length; i++) hash = s.charCodeAt(i) + ((hash << 5) - hash);
  return palette[Math.abs(hash) % palette.length];
}

function getAttachmentIcon(cat, mime, fname) {
  const c = String(cat || "").toLowerCase();
  const f = String(fname || "").toLowerCase();
  if (c.includes("image") || /\.(png|jpg|jpeg|gif|webp|bmp|svg)$/.test(f)) return "🖼️";
  if (c.includes("pdf") || f.endsWith(".pdf")) return "📕";
  if (c.includes("spreadsheet") || /\.(xlsx|xls|csv)$/.test(f)) return "📊";
  if (c.includes("word") || /\.(docx|doc|rtf)$/.test(f)) return "📘";
  if (c.includes("presentation") || /\.(pptx|ppt)$/.test(f)) return "📙";
  if (c.includes("archive") || /\.(zip|7z|rar|tar|gz)$/.test(f)) return "📦";
  if (c.includes("message") || /\.(msg|eml)$/.test(f)) return "📧";
  if (c.includes("calendar") || f.endsWith(".ics")) return "📅";
  if (c.includes("audio") || /\.(mp3|wav|ogg)$/.test(f)) return "🎵";
  if (c.includes("video") || /\.(mp4|mov|avi)$/.test(f)) return "🎬";
  return "📄";
}

function resolveAttachmentUrl(relPath) {
  if (!relPath) return "";
  if (window.location.protocol.startsWith("http")) {
    const caseName = (rawData.stats && rawData.stats.case_name) || "";
    if (caseName) {
      return `/cases/${encodeURIComponent(caseName)}/${relPath}`;
    }
    return `/${relPath}`;
  }
  return relPath;
}

function highlightTextSafe(text, kw) {
  if (!text) return "";
  const escaped = esc(text);
  if (!kw || !kw.trim()) return escaped;
  try {
    const cleanKw = kw.trim().replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const flags = searchCaseSensitive ? "g" : "gi";
    const rx = new RegExp(`(${cleanKw})`, flags);
    return escaped.replace(rx, '<mark class="kw-highlight">$1</mark>');
  } catch (e) {
    return escaped;
  }
}

function highlightHtmlSafe(htmlStr, kw) {
  if (!htmlStr) return "";
  if (!kw || !kw.trim()) return htmlStr;
  try {
    const cleanKw = kw.trim().replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const flags = searchCaseSensitive ? "g" : "gi";
    const rx = new RegExp(`(${cleanKw})`, flags);
    return htmlStr.replace(/(<[^>]+>)|([^<]+)/g, (match, tag, textNode) => {
      if (tag) return tag;
      return textNode.replace(rx, '<mark class="kw-highlight">$1</mark>');
    });
  } catch (e) {
    return htmlStr;
  }
}

function initViewer() {
  if (window.location.protocol.startsWith("http")) {
    const cmBtn = document.getElementById("btnCaseManager");
    if (cmBtn) cmBtn.style.display = "inline-flex";
  }

  const st = rawData.stats || {};
  document.getElementById("headerCaseBadge").innerText = "📁 " + (st.case_name || "Outlook Case");
  const uLabel = st.email ? `${st.user || "User"} <${st.email}>` : (st.user || st.tenant || "Outlook Evidence");
  document.getElementById("headerUserBadge").innerText = "👤 " + uLabel;

  // Build flat messages list
  allMessagesFlat = [];
  (rawData.mail_chains || []).forEach(c => {
    (c.messages || []).forEach(m => {
      allMessagesFlat.push({ chain: c, msg: m });
    });
  });
  allMessagesFlat.sort((a, b) => String(b.msg.time_sort || "").localeCompare(String(a.msg.time_sort || "")));

  renderFoldersTree();
  renderChainsList();

  if ((rawData.mail_chains || []).length > 0) {
    selectMailChain(rawData.mail_chains[0].chain_id);
  } else if ((rawData.leveldb_records || []).length > 0) {
    renderEmptyMailWithLevelDBNotice();
  }
}

function renderEmptyMailWithLevelDBNotice() {
  const pane = document.getElementById("readingPaneContainer");
  const st = rawData.stats || {};
  const idents = (st.account_identities || []).map(a => `<span class="recip-pill"><b>${esc(a.email)}</b> (ID: ${esc(a.identity_id)})</span>`).join(" ");
  pane.innerHTML = `
    <div class="empty-placeholder">
      <div class="icon">🗄️</div>
      <h3>New Outlook (Olk) LevelDB & Configuration Evidence Loaded</h3>
      <p style="font-size:13.5px; max-width:560px; line-height:1.6;">
        No offline cached email bodies were found in this folder, but <b>${(rawData.leveldb_records || []).length}</b> New Outlook LevelDB / LocalStorage / Telemetry records were decoded.
      </p>
      ${idents ? `<div style="margin:8px 0;"><b>Configured Mailbox Identities:</b><br>${idents}</div>` : ""}
      <div style="display:flex; gap:10px; margin-top:10px;">
        <button class="btn-pane-action primary" onclick="switchTab('leveldb')">🗄️ Inspect Decoded LevelDB Records (${(rawData.leveldb_records || []).length})</button>
        <button class="btn-pane-action" onclick="switchTab('overview')">📊 View Case Audit Summary</button>
      </div>
    </div>
  `;
}

function getFolderIcon(name) {
  const n = String(name || "").toLowerCase();
  if (n === "inbox") return "📥";
  if (n.includes("sent")) return "📤";
  if (n.includes("draft")) return "📝";
  if (n.includes("deleted") || n.includes("trash") || n.includes("orphan")) return "🗑️";
  if (n.includes("junk") || n.includes("spam")) return "🚫";
  if (n.includes("archive")) return "🗄️";
  if (n.includes("outbox")) return "📮";
  return "📁";
}

function renderFoldersTree() {
  const container = document.getElementById("foldersListContainer");
  const totalMsgs = (rawData.stats && rawData.stats.total_messages) || allMessagesFlat.length;
  const totalChains = (rawData.mail_chains || []).length;

  let html = `
    <div class="folder-item ${selectedFolder === 'ALL' ? 'active' : ''}" onclick="selectFolder('ALL')">
      <div class="folder-name-wrap">
        <span>📬</span>
        <span class="folder-name-text">All Mailboxes</span>
      </div>
      <span class="folder-count-badge">${listGroupingMode === 'chains' ? totalChains : totalMsgs}</span>
    </div>
  `;

  (rawData.folders || []).forEach(f => {
    const isAct = selectedFolder === f.name;
    const cnt = listGroupingMode === "chains" ? (f.total_chains || f.total_messages || 0) : (f.total_messages || 0);
    html += `
      <div class="folder-item ${isAct ? 'active' : ''}" onclick="selectFolder('${esc(f.name)}')">
        <div class="folder-name-wrap">
          <span>${getFolderIcon(f.name)}</span>
          <span class="folder-name-text" title="${esc(f.name)}">${esc(f.name)}</span>
        </div>
        <span class="folder-count-badge">${cnt}</span>
      </div>
    `;
  });

  container.innerHTML = html;
}

function selectFolder(folderName) {
  selectedFolder = folderName;
  document.getElementById("currentFolderLabel").innerText = folderName === "ALL" ? "All Mailboxes" : folderName;
  renderFoldersTree();
  renderChainsList();
}

function setQuickFilter(filterType, pillEl) {
  quickFilter = filterType;
  document.querySelectorAll(".chains-pane .filter-pill").forEach(el => el.classList.remove("active"));
  if (pillEl) pillEl.classList.add("active");
  renderChainsList();
}

function setListGroupingMode(mode) {
  listGroupingMode = mode;
  document.getElementById("btnModeChains").classList.toggle("active", mode === "chains");
  document.getElementById("btnModeFlat").classList.toggle("active", mode === "flat");
  renderFoldersTree();
  renderChainsList();
}

function chainMatchesFilters(chain, filterQuery) {
  if (selectedFolder !== "ALL") {
    const inFolder = (chain.folders || []).includes(selectedFolder) || chain.primary_folder === selectedFolder;
    if (!inFolder) return false;
  }
  if (quickFilter === "multi" && (chain.msg_count || 0) < 2) return false;
  if (quickFilter === "att" && (chain.attachment_count || 0) === 0) return false;
  if (quickFilter === "high" && chain.importance !== "High") return false;
  if (quickFilter === "deleted" && !chain.has_deleted) return false;
  if (quickFilter === "unread" && !chain.has_unread) return false;

  if (filterQuery) {
    const q = filterQuery.toLowerCase();
    const subjMatch = String(chain.subject || "").toLowerCase().includes(q);
    const partMatch = (chain.participants || []).some(p => String(p).toLowerCase().includes(q));
    const msgMatch = (chain.messages || []).some(m =>
      String(m.body_plain || "").toLowerCase().includes(q) ||
      String(m.subject || "").toLowerCase().includes(q) ||
      (m.attachments || []).some(a => String(a.fileName || "").toLowerCase().includes(q))
    );
    if (!subjMatch && !partMatch && !msgMatch) return false;
  }
  return true;
}

function renderChainsList() {
  const container = document.getElementById("chainsListContainer");
  const filterQuery = (document.getElementById("chainFilterInput").value || "").trim();

  if (listGroupingMode === "chains") {
    const filtered = (rawData.mail_chains || []).filter(c => chainMatchesFilters(c, filterQuery));
    if (filtered.length === 0) {
      container.innerHTML = `<div class="empty-placeholder" style="height:260px;"><div class="icon">📭</div><div>No mail chains match the current filter.</div></div>`;
      return;
    }

    container.innerHTML = filtered.map(c => {
      const isAct = c.chain_id === activeChainId;
      const sendersStr = (c.senders || []).join(", ") || "Unknown Sender";
      const avatarColor = getAvatarColor(sendersStr);
      const initials = getInitials(c.senders && c.senders[0] ? c.senders[0] : sendersStr);
      const timeShort = (c.last_time_local || c.last_time_utc || "").slice(0, 16);

      let badgesHtml = `<span class="mini-badge">${esc(c.primary_folder || "Inbox")}</span>`;
      if ((c.msg_count || 0) > 1) {
        badgesHtml += `<span class="mini-badge chain">🔗 ${c.msg_count} mails in chain</span>`;
      }
      if ((c.attachment_count || 0) > 0) {
        badgesHtml += `<span class="mini-badge att">📎 ${c.attachment_count}</span>`;
      }
      if (c.importance === "High") {
        badgesHtml += `<span class="mini-badge high">❗ High</span>`;
      }
      if (c.has_deleted) {
        badgesHtml += `<span class="mini-badge deleted">🗑️ Deleted/Recovered</span>`;
      }

      return `
        <div class="chain-list-item ${isAct ? 'active' : ''} ${c.has_unread ? 'unread' : ''}" onclick="selectMailChain('${esc(c.chain_id)}')">
          <div class="chain-avatar" style="background:${avatarColor};">
            ${esc(initials)}
            ${c.msg_count > 1 ? `<span class="chain-count-pill">${c.msg_count}</span>` : ""}
          </div>
          <div class="chain-item-body">
            <div class="chain-item-top">
              <span class="chain-item-senders">${highlightTextSafe(sendersStr, activeSearchKeyword || filterQuery)}</span>
              <span class="chain-item-time">${esc(timeShort)}</span>
            </div>
            <div class="chain-item-subject">${highlightTextSafe(c.subject, activeSearchKeyword || filterQuery)}</div>
            <div class="chain-item-snippet">${highlightTextSafe(c.last_snippet || "", activeSearchKeyword || filterQuery)}</div>
            <div class="chain-item-badges">${badgesHtml}</div>
          </div>
        </div>
      `;
    }).join("");
  } else {
    // Flat individual message mode
    const filteredFlat = allMessagesFlat.filter(({ chain, msg }) => {
      if (selectedFolder !== "ALL" && msg.folder !== selectedFolder) return false;
      if (quickFilter === "multi" && (chain.msg_count || 0) < 2) return false;
      if (quickFilter === "att" && (msg.attachments || []).length === 0) return false;
      if (quickFilter === "high" && msg.importance !== "High") return false;
      if (quickFilter === "deleted" && !msg.is_deleted) return false;
      if (quickFilter === "unread" && msg.is_read) return false;
      if (filterQuery) {
        const q = filterQuery.toLowerCase();
        const mMatch =
          String(msg.subject || "").toLowerCase().includes(q) ||
          String(msg.sender_display || "").toLowerCase().includes(q) ||
          String(msg.body_plain || "").toLowerCase().includes(q) ||
          (msg.attachments || []).some(a => String(a.fileName || "").toLowerCase().includes(q));
        if (!mMatch) return false;
      }
      return true;
    });

    if (filteredFlat.length === 0) {
      container.innerHTML = `<div class="empty-placeholder" style="height:260px;"><div class="icon">📭</div><div>No emails match the current filter.</div></div>`;
      return;
    }

    container.innerHTML = filteredFlat.map(({ chain, msg }) => {
      const isAct = chain.chain_id === activeChainId && msg.id === activeHighlightMsgId;
      const avatarColor = getAvatarColor(msg.sender_name || msg.sender_email);
      const initials = getInitials(msg.sender_name || msg.sender_email);
      const timeShort = (msg.time_local || msg.time_utc || "").slice(0, 16);
      const attCnt = (msg.attachments || []).length;
      return `
        <div class="chain-list-item ${isAct ? 'active' : ''} ${!msg.is_read ? 'unread' : ''}" onclick="selectMailChain('${esc(chain.chain_id)}', '${esc(msg.id)}')">
          <div class="chain-avatar" style="background:${avatarColor};">${esc(initials)}</div>
          <div class="chain-item-body">
            <div class="chain-item-top">
              <span class="chain-item-senders">${highlightTextSafe(msg.sender_name || msg.sender_email, activeSearchKeyword || filterQuery)}</span>
              <span class="chain-item-time">${esc(timeShort)}</span>
            </div>
            <div class="chain-item-subject">${highlightTextSafe(msg.subject, activeSearchKeyword || filterQuery)}</div>
            <div class="chain-item-snippet">${highlightTextSafe((msg.body_plain || "").slice(0, 120), activeSearchKeyword || filterQuery)}</div>
            <div class="chain-item-badges">
              <span class="mini-badge">${esc(msg.folder || "Inbox")}</span>
              <span class="mini-badge chain">Msg #${msg.chain_index}/${chain.msg_count}</span>
              ${attCnt > 0 ? `<span class="mini-badge att">📎 ${attCnt}</span>` : ""}
            </div>
          </div>
        </div>
      `;
    }).join("");
  }
}

function selectMailChain(chainId, focusMsgId = null) {
  activeChainId = chainId;
  activeHighlightMsgId = focusMsgId;
  renderChainsList();

  const chain = (rawData.mail_chains || []).find(c => c.chain_id === chainId);
  const pane = document.getElementById("readingPaneContainer");
  if (!chain) {
    pane.innerHTML = `<div class="empty-placeholder"><div class="icon">📭</div><div>Mail chain not found.</div></div>`;
    return;
  }

  let msgs = [...(chain.messages || [])];
  if (chainSortReverse) msgs.reverse();

  const foldersBadges = (chain.folders || []).map(f => `<span class="mini-badge">${getFolderIcon(f)} ${esc(f)}</span>`).join(" ");

  // Build Chain-Level Attachments Summary Strip
  let chainAttStripHtml = "";
  if ((chain.attachments || []).length > 0) {
    const chips = chain.attachments.map(att => {
      const icon = getAttachmentIcon(att.category, att.contentType, att.fileName);
      return `
        <div class="chain-att-chip" onclick="openAttachmentPreview('${esc(att.att_id)}')" title="Click to preview ${esc(att.fileName)} (${formatBytes(att.size)})">
          <span>${icon}</span>
          <span style="font-weight:600; color:var(--text-main);">${esc(att.fileName)}</span>
          <span style="color:var(--text-muted); font-size:11px;">(${formatBytes(att.size)})</span>
        </div>
      `;
    }).join("");
    chainAttStripHtml = `
      <div class="chain-attachments-strip">
        <span style="font-size:11.5px; font-weight:700; color:var(--primary); white-space:nowrap;">📎 Chain Attachments (${chain.attachments.length}):</span>
        ${chips}
      </div>
    `;
  }

  // Render Each Email in the Mail Chain
  const messagesCardsHtml = msgs.map((m, idx) => {
    const avatarColor = getAvatarColor(m.sender_name || m.sender_email);
    const initials = getInitials(m.sender_name || m.sender_email);
    const isTarget = focusMsgId && m.id === focusMsgId;
    const stepLabel = m.chain_index === 1
      ? `Original Email (#1 of ${chain.msg_count})`
      : `Chain Reply #${m.chain_index} of ${chain.msg_count}${m.reply_depth > 0 ? ` • Depth L${m.reply_depth}` : ""}`;

    const toPills = (m.to_recipients || []).map(r => `<span class="recip-pill">${highlightTextSafe(r.display || r.email || r.name, activeSearchKeyword)}</span>`).join("") || `<span style="color:var(--text-light);">—</span>`;
    const ccRow = (m.cc_recipients && m.cc_recipients.length > 0)
      ? `<div class="env-label">Cc:</div><div class="env-val">${m.cc_recipients.map(r => `<span class="recip-pill">${highlightTextSafe(r.display || r.email || r.name, activeSearchKeyword)}</span>`).join("")}</div>`
      : "";
    const bccRow = (m.bcc_recipients && m.bcc_recipients.length > 0)
      ? `<div class="env-label">Bcc:</div><div class="env-val">${m.bcc_recipients.map(r => `<span class="recip-pill bcc">🕵️ ${highlightTextSafe(r.display || r.email || r.name, activeSearchKeyword)}</span>`).join("")}</div>`
      : "";
    const replyToRow = (m.reply_to && m.reply_to.length > 0)
      ? `<div class="env-label">Reply-To:</div><div class="env-val">${m.reply_to.map(r => `<span class="recip-pill">${esc(r.display)}</span>`).join("")}</div>`
      : "";

    // Message Attachments Block
    let msgAttHtml = "";
    if ((m.attachments || []).length > 0) {
      const cards = m.attachments.map(att => {
        const icon = getAttachmentIcon(att.category, att.contentType, att.fileName);
        const fileUrl = resolveAttachmentUrl(att.rel_path);
        const isImg = att.category === "Image" && att.extracted && fileUrl;
        const thumbHtml = isImg
          ? `<img src="${esc(fileUrl)}" alt="${esc(att.fileName)}" onerror="this.parentElement.innerText='🖼️'">`
          : `<span>${icon}</span>`;
        const shaShort = att.sha256 ? `SHA256: ${att.sha256.slice(0, 12)}...` : "Metadata Recorded";

        return `
          <div class="att-card">
            <div class="att-icon-thumb" onclick="openAttachmentPreview('${esc(att.att_id)}')" style="cursor:pointer;">
              ${thumbHtml}
            </div>
            <div class="att-meta">
              <div class="att-filename" title="${esc(att.fileName)}">${highlightTextSafe(att.fileName, activeSearchKeyword)}</div>
              <div class="att-subinfo">
                <span><b>${formatBytes(att.size)}</b></span>
                <span>•</span>
                <span>${esc(att.category || att.contentType)}</span>
                ${att.isInline ? `<span class="mini-badge att">Inline CID</span>` : ""}
              </div>
              <div class="att-subinfo" style="font-family:Consolas, monospace; font-size:10px;" title="SHA-256: ${esc(att.sha256 || 'N/A')}">
                ${esc(shaShort)}
              </div>
            </div>
            <div class="att-actions">
              <button class="btn-att" onclick="openAttachmentPreview('${esc(att.att_id)}')">👁️ Preview</button>
              ${att.extracted && fileUrl ? `<a class="btn-att" href="${esc(fileUrl)}" download="${esc(att.fileName)}">⬇️ Save</a>` : ""}
            </div>
          </div>
        `;
      }).join("");

      msgAttHtml = `
        <div class="msg-attachments-bar">
          <div style="font-size:11.5px; font-weight:700; color:var(--text-muted);">📎 Attached Files on Message #${m.chain_index} (${m.attachments.length}):</div>
          <div class="msg-att-grid">${cards}</div>
        </div>
      `;
    }

    // Prepare Rich HTML, Plain Text, and Forensic Headers/MAPI views
    const hasRichHtml = Boolean(m.body_html_clean && m.body_html_clean.trim());
    const richBodyContent = hasRichHtml
      ? `<div class="email-render-scope">${highlightHtmlSafe(m.body_html_clean, activeSearchKeyword)}</div>`
      : `<div class="plain-text-box">${highlightTextSafe(m.body_plain || "(Empty Message Body)", activeSearchKeyword)}</div>`;

    const plainBodyContent = `<div class="plain-text-box">${highlightTextSafe(m.body_plain || "(No Plain Text Body)", activeSearchKeyword)}</div>`;

    // Build Forensic Headers & MAPI Table
    let mapiRows = "";
    const mapiObj = m.mapi_properties || {};
    Object.keys(mapiObj).forEach(k => {
      mapiRows += `<tr><td style="font-family:Consolas,monospace; font-weight:600; width:240px;">${esc(k)}</td><td style="font-family:Consolas,monospace; word-break:break-all;">${esc(mapiObj[k])}</td></tr>`;
    });

    let parsedHdrRows = "";
    const pHdrs = m.parsed_headers || {};
    Object.keys(pHdrs).forEach(k => {
      parsedHdrRows += `<tr><td style="font-family:Consolas,monospace; font-weight:600; width:220px;">${esc(k)}</td><td style="font-family:Consolas,monospace; word-break:break-all;">${esc(pHdrs[k])}</td></tr>`;
    });

    const forensicMetaContent = `
      <div class="headers-forensic-box">
        <div class="data-table-wrapper">
          <table class="forensic-table">
            <thead><tr><th colspan="2">🔬 Message Threading & Forensic Identifiers</th></tr></thead>
            <tbody>
              <tr><td style="width:220px; font-weight:600;">Internal Record ID</td><td style="font-family:Consolas,monospace;">${esc(m.id)}</td></tr>
              <tr><td style="font-weight:600;">Chain / Conversation ID</td><td style="font-family:Consolas,monospace;">${esc(chain.chain_id)} (Position #${m.chain_index} of ${chain.msg_count}, Reply Depth: ${m.reply_depth})</td></tr>
              <tr><td style="font-weight:600;">Internet Message-ID</td><td style="font-family:Consolas,monospace;">${esc(m.internet_message_id || "N/A")}</td></tr>
              <tr><td style="font-weight:600;">In-Reply-To</td><td style="font-family:Consolas,monospace;">${esc(m.in_reply_to || "N/A")} ${m.parent_msg_id ? `(Linked Parent Record: ${esc(m.parent_msg_id)})` : ""}</td></tr>
              <tr><td style="font-weight:600;">References Chain</td><td style="font-family:Consolas,monospace; word-break:break-all;">${esc(m.references || "N/A")}</td></tr>
              <tr><td style="font-weight:600;">MAPI ConversationIndex</td><td style="font-family:Consolas,monospace; word-break:break-all;">${esc(m.conversation_index || "N/A")} ${m.conv_index_guid ? `<br><span style="color:var(--primary);">Decoded Thread GUID: ${esc(m.conv_index_guid)} • MAPI Level: ${m.conv_index_depth}</span>` : ""}</td></tr>
              <tr><td style="font-weight:600;">MAPI Item Class</td><td style="font-family:Consolas,monospace;">${esc(m.item_class || "IPM.Note")}</td></tr>
              <tr><td style="font-weight:600;">Mailbox Folder</td><td>${esc(m.folder)} ${m.folder_id ? `(Folder ID: ${esc(m.folder_id)})` : ""}</td></tr>
              <tr><td style="font-weight:600;">Timestamps (Dual Zone)</td><td><b>IST (UTC+5:30):</b> ${esc(m.time_local || "N/A")} &nbsp;|&nbsp; <b>UTC:</b> ${esc(m.time_utc || "N/A")}</td></tr>
              <tr><td style="font-weight:600;">Evidence Source File</td><td style="font-family:Consolas,monospace;">${esc(m.source_file)}</td></tr>
            </tbody>
          </table>
        </div>
        ${parsedHdrRows ? `<div class="data-table-wrapper"><table class="forensic-table"><thead><tr><th colspan="2">📨 Decoded RFC 5322 Internet Transport Headers</th></tr></thead><tbody>${parsedHdrRows}</tbody></table></div>` : ""}
        ${mapiRows ? `<div class="data-table-wrapper"><table class="forensic-table"><thead><tr><th colspan="2">🗂️ Extracted MAPI Record Entry Properties</th></tr></thead><tbody>${mapiRows}</tbody></table></div>` : ""}
        ${m.transport_headers ? `<div><div style="font-weight:700; font-size:12px; margin-bottom:4px;">Raw Transport Headers Block:</div><div class="plain-text-box" style="font-size:11.5px;">${esc(m.transport_headers)}</div></div>` : ""}
      </div>
    `;

    const indentPx = Math.min((m.reply_depth || 0) * 14, 56);

    return `
      <div class="email-chain-node" id="msg-node-${esc(m.id)}" style="margin-left:${indentPx}px;">
        ${idx > 0 ? `<div class="email-chain-connector"></div>` : ""}
        <div class="email-card ${isTarget ? 'highlight-target' : ''}">
          <div class="email-card-header" onclick="toggleEmailCardBody('${esc(m.id)}')">
            <div class="email-card-top-row">
              <div class="email-sender-box">
                <div class="email-sender-avatar" style="background:${avatarColor};">${esc(initials)}</div>
                <div class="email-sender-details">
                  <div class="email-sender-title">
                    <span>${highlightTextSafe(m.sender_name || m.sender_email, activeSearchKeyword)}</span>
                    ${m.sender_email ? `<span class="email-sender-addr">&lt;${highlightTextSafe(m.sender_email, activeSearchKeyword)}&gt;</span>` : ""}
                    <span class="email-step-badge">${esc(stepLabel)}</span>
                    <span class="mini-badge">${getFolderIcon(m.folder)} ${esc(m.folder)}</span>
                    ${m.importance === "High" ? `<span class="mini-badge high">❗ High Importance</span>` : ""}
                    ${m.is_deleted ? `<span class="mini-badge deleted">🗑️ Deleted / Recovered</span>` : ""}
                    ${m.is_draft ? `<span class="mini-badge">📝 Draft</span>` : ""}
                  </div>
                  <div style="font-size:12px; color:var(--text-muted); margin-top:2px;">
                    <b>Subject:</b> ${highlightTextSafe(m.subject, activeSearchKeyword)}
                  </div>
                </div>
              </div>
              <div class="email-timestamps-box">
                <div><b>${esc(m.time_local || m.time_utc || "Timestamp N/A")}</b> <span style="font-size:10px; opacity:0.8;">(Local/IST)</span></div>
                ${m.time_utc ? `<div style="font-size:11px; color:var(--text-light);">🌐 ${esc(m.time_utc)}</div>` : ""}
              </div>
            </div>

            <div class="email-envelope-grid" onclick="event.stopPropagation()">
              <div class="env-label">From:</div>
              <div class="env-val"><span class="recip-pill"><b>${highlightTextSafe(m.sender_display || m.sender_name, activeSearchKeyword)}</b></span></div>
              <div class="env-label">To:</div>
              <div class="env-val">${toPills}</div>
              ${ccRow}
              ${bccRow}
              ${replyToRow}
            </div>
          </div>

          <div id="email-body-wrap-${esc(m.id)}">
            ${msgAttHtml}
            <div class="email-view-toolbar">
              <div class="body-mode-tabs">
                <button class="body-tab-btn active" id="tab-btn-rich-${esc(m.id)}" onclick="switchMessageBodyTab('${esc(m.id)}', 'rich')">🖼️ Rich Email View</button>
                <button class="body-tab-btn" id="tab-btn-plain-${esc(m.id)}" onclick="switchMessageBodyTab('${esc(m.id)}', 'plain')">📝 Unaltered Plain Text</button>
                <button class="body-tab-btn" id="tab-btn-meta-${esc(m.id)}" onclick="switchMessageBodyTab('${esc(m.id)}', 'meta')">🔬 Headers & Forensic Metadata</button>
              </div>
              <span style="font-size:11px; color:var(--text-light); font-family:Consolas,monospace;">Source: ${esc(m.source_file)}</span>
            </div>

            <div class="email-body-container" id="body-pane-rich-${esc(m.id)}">${richBodyContent}</div>
            <div class="email-body-container" id="body-pane-plain-${esc(m.id)}" style="display:none;">${plainBodyContent}</div>
            <div class="email-body-container" id="body-pane-meta-${esc(m.id)}" style="display:none;">${forensicMetaContent}</div>
          </div>
        </div>
      </div>
    `;
  }).join("");

  pane.innerHTML = `
    <div class="chain-header-bar">
      <div class="chain-header-top">
        <div style="flex:1; min-width:260px;">
          <div class="chain-subject-title">${highlightTextSafe(chain.subject, activeSearchKeyword)}</div>
          <div class="chain-meta-sub">
            ${foldersBadges}
            <span>•</span>
            <span><b>${chain.msg_count}</b> ${chain.msg_count === 1 ? "Email" : "Emails in Chain"}</span>
            <span>•</span>
            <span><b>${(chain.participants || []).length}</b> Participants</span>
            <span>•</span>
            <span><b>${chain.attachment_count || 0}</b> Attachments</span>
            ${chain.first_time_local ? `<span>•</span><span>Timeline: <b>${esc(chain.first_time_local)}</b> &rarr; <b>${esc(chain.last_time_local)}</b></span>` : ""}
          </div>
        </div>
        <div class="chain-actions-group">
          <button class="btn-pane-action" onclick="toggleAllMessagesInChain()">↕️ Expand / Collapse All</button>
          <button class="btn-pane-action" onclick="reverseChainOrder()">🔄 ${chainSortReverse ? "Newest First" : "Oldest First"}</button>
          <button class="btn-pane-action primary" onclick="exportMailChainHtml('${esc(chain.chain_id)}')">🖨️ Export Mail Chain HTML / PDF</button>
        </div>
      </div>
      ${chainAttStripHtml}
    </div>
    <div class="chain-messages-scroll" id="chainMessagesScrollBox">
      ${messagesCardsHtml}
    </div>
  `;

  if (focusMsgId) {
    setTimeout(() => {
      const targetEl = document.getElementById("msg-node-" + focusMsgId);
      if (targetEl) targetEl.scrollIntoView({ behavior: "smooth", block: "center" });
    }, 80);
  }
}

function toggleEmailCardBody(msgId) {
  const wrap = document.getElementById("email-body-wrap-" + msgId);
  if (wrap) {
    wrap.style.display = wrap.style.display === "none" ? "block" : "none";
  }
}

let allCollapsed = false;
function toggleAllMessagesInChain() {
  allCollapsed = !allCollapsed;
  document.querySelectorAll("[id^='email-body-wrap-']").forEach(el => {
    el.style.display = allCollapsed ? "none" : "block";
  });
}

function reverseChainOrder() {
  chainSortReverse = !chainSortReverse;
  if (activeChainId) selectMailChain(activeChainId, activeHighlightMsgId);
}

function switchMessageBodyTab(msgId, tabMode) {
  ["rich", "plain", "meta"].forEach(mode => {
    const btn = document.getElementById(`tab-btn-${mode}-${msgId}`);
    const pane = document.getElementById(`body-pane-${mode}-${msgId}`);
    if (btn) btn.classList.toggle("active", mode === tabMode);
    if (pane) pane.style.display = mode === tabMode ? "block" : "none";
  });
}

function openAttachmentPreview(attId) {
  const att = (rawData.attachments || []).find(a => a.att_id === attId);
  if (!att) return;
  const modal = document.getElementById("previewModal");
  const titleEl = document.getElementById("modalTitle");
  const bodyEl = document.getElementById("modalBodyContent");

  const icon = getAttachmentIcon(att.category, att.contentType, att.fileName);
  titleEl.innerHTML = `<span>${icon}</span> <span>${esc(att.fileName)}</span> <span style="font-size:12px; opacity:0.8;">(${formatBytes(att.size)})</span>`;

  const fileUrl = resolveAttachmentUrl(att.rel_path);
  let previewBox = "";

  if (att.extracted && fileUrl) {
    const cat = String(att.category || "").toLowerCase();
    const fn = String(att.fileName || "").toLowerCase();
    if (cat.includes("image") || /\.(png|jpg|jpeg|gif|webp|bmp|svg)$/.test(fn)) {
      previewBox = `<div style="text-align:center; background:var(--bg-app); padding:16px; border-radius:8px; border:1px solid var(--border);"><img src="${esc(fileUrl)}" style="max-width:100%; max-height:60vh; object-fit:contain; border-radius:6px;"></div>`;
    } else if (cat.includes("pdf") || fn.endsWith(".pdf") || fn.endsWith(".html") || fn.endsWith(".htm") || fn.endsWith(".txt") || fn.endsWith(".log") || fn.endsWith(".csv") || fn.endsWith(".json")) {
      previewBox = `<iframe src="${esc(fileUrl)}" style="width:100%; height:55vh; border:1px solid var(--border); border-radius:6px; background:#fff;"></iframe>`;
    } else if (cat.includes("video") || fn.endsWith(".mp4")) {
      previewBox = `<video controls src="${esc(fileUrl)}" style="width:100%; max-height:55vh; border-radius:6px;"></video>`;
    } else if (cat.includes("audio") || /\.(mp3|wav)$/.test(fn)) {
      previewBox = `<audio controls src="${esc(fileUrl)}" style="width:100%;"></audio>`;
    } else {
      previewBox = `<div style="padding:24px; text-align:center; background:var(--bg-app); border-radius:8px; border:1px solid var(--border);">
        <div style="font-size:42px; margin-bottom:8px;">${icon}</div>
        <div style="font-weight:700; margin-bottom:6px;">Binary Attachment Extracted Losslessly</div>
        <div style="font-size:12.5px; color:var(--text-muted); margin-bottom:14px;">Click Download below to open <b>${esc(att.fileName)}</b> in its native application.</div>
        <a href="${esc(fileUrl)}" download="${esc(att.fileName)}" class="btn-pane-action primary" style="display:inline-flex;">⬇️ Download ${esc(att.fileName)} (${formatBytes(att.size)})</a>
      </div>`;
    }
  } else {
    previewBox = `<div style="padding:20px; text-align:center; background:var(--bg-app); border-radius:8px; border:1px solid var(--border); color:var(--text-muted);">
      Attachment metadata recorded in forensic database, binary stream was not cached locally on disk.
    </div>`;
  }

  bodyEl.innerHTML = `
    ${previewBox}
    <div class="data-table-wrapper">
      <table class="forensic-table">
        <thead><tr><th colspan="2">🔬 Forensic Attachment Verification & Lineage</th></tr></thead>
        <tbody>
          <tr><td style="width:190px; font-weight:600;">Original Filename</td><td><b>${esc(att.fileName)}</b></td></tr>
          <tr><td style="font-weight:600;">Saved Evidence File</td><td style="font-family:Consolas,monospace;">${esc(att.rel_path || "N/A")}</td></tr>
          <tr><td style="font-weight:600;">Category & MIME Type</td><td>${esc(att.category)} (${esc(att.contentType)}) ${att.isInline ? "• Inline CID: " + esc(att.contentId) : ""}</td></tr>
          <tr><td style="font-weight:600;">Exact Size</td><td>${(att.size || 0).toLocaleString()} bytes (${formatBytes(att.size)})</td></tr>
          <tr><td style="font-weight:600;">SHA-256 Integrity Hash</td><td style="font-family:Consolas,monospace; word-break:break-all;">${esc(att.sha256 || "N/A")}</td></tr>
          <tr><td style="font-weight:600;">Parent Email Subject</td><td>${esc(att.subject || "N/A")}</td></tr>
          <tr><td style="font-weight:600;">Sender & Timestamp</td><td>${esc(att.sender || "N/A")} • ${esc(att.time_local || "N/A")}</td></tr>
        </tbody>
      </table>
    </div>
    <div style="display:flex; justify-content:flex-end; gap:10px;">
      ${att.chain_id ? `<button class="btn-pane-action" onclick="closePreviewModal(); switchTab('mail'); selectMailChain('${esc(att.chain_id)}', '${esc(att.msg_id)}');">📬 Open Parent Mail Chain</button>` : ""}
      ${att.extracted && fileUrl ? `<a href="${esc(fileUrl)}" download="${esc(att.fileName)}" class="btn-pane-action primary">⬇️ Download Attachment</a>` : ""}
      <button class="btn-pane-action" onclick="closePreviewModal()">Close</button>
    </div>
  `;
  modal.classList.add("active");
}

function openImageModal(srcUrl) {
  const modal = document.getElementById("previewModal");
  document.getElementById("modalTitle").innerText = "🖼️ Inline Email Image Preview";
  document.getElementById("modalBodyContent").innerHTML = `
    <div style="text-align:center; background:var(--bg-app); padding:16px; border-radius:8px;">
      <img src="${esc(srcUrl)}" style="max-width:100%; max-height:72vh; object-fit:contain; border-radius:6px;">
    </div>
    <div style="display:flex; justify-content:flex-end; gap:10px;">
      <a href="${esc(srcUrl)}" download class="btn-pane-action primary">⬇️ Save Image</a>
      <button class="btn-pane-action" onclick="closePreviewModal()">Close</button>
    </div>
  `;
  modal.classList.add("active");
}

function closePreviewModal() {
  document.getElementById("previewModal").classList.remove("active");
}

function switchTab(tabName) {
  activeTab = tabName;
  document.querySelectorAll(".nav-tab").forEach(el => {
    el.classList.toggle("active", el.getAttribute("data-tab") === tabName);
  });
  ["mail", "search", "attachments", "calendar", "contacts", "leveldb", "overview"].forEach(t => {
    const viewEl = document.getElementById("view-" + t);
    if (viewEl) {
      viewEl.style.display = t === tabName ? "flex" : "none";
    }
  });

  if (tabName === "search") renderSearchView();
  else if (tabName === "attachments") renderAttachmentsView();
  else if (tabName === "calendar") renderCalendarView();
  else if (tabName === "contacts") renderContactsView();
  else if (tabName === "leveldb") renderLevelDBView();
  else if (tabName === "overview") renderOverviewView();
}

function toggleCaseSensitive() {
  searchCaseSensitive = !searchCaseSensitive;
  const btn = document.getElementById("btnCaseSensitive");
  if (btn) btn.classList.toggle("active", searchCaseSensitive);
  const val = document.getElementById("globalSearchInput").value;
  if (val) runGlobalSearch(val);
}

let searchDebounceTimer = null;
function handleGlobalSearchInput(val) {
  activeSearchKeyword = val;
  if (searchDebounceTimer) clearTimeout(searchDebounceTimer);
  searchDebounceTimer = setTimeout(() => {
    if (val && val.trim().length > 0) {
      runGlobalSearch(val);
    } else {
      renderChainsList();
      if (activeChainId) selectMailChain(activeChainId, activeHighlightMsgId);
    }
  }, 220);
}

function clearGlobalSearch() {
  document.getElementById("globalSearchInput").value = "";
  activeSearchKeyword = "";
  renderChainsList();
  if (activeChainId) selectMailChain(activeChainId, activeHighlightMsgId);
  if (activeTab === "search") renderSearchView();
}

function runGlobalSearch(query) {
  activeSearchKeyword = (query || "").trim();
  if (activeTab !== "search") {
    switchTab("search");
  } else {
    renderSearchView();
  }
}

function renderSearchView() {
  const container = document.getElementById("view-search");
  const qRaw = (activeSearchKeyword || document.getElementById("globalSearchInput").value || "").trim();
  const q = searchCaseSensitive ? qRaw : qRaw.toLowerCase();

  // Compute distinct word cloud across all messages and attachments
  const wordCounts = {};
  const tokenRx = /[a-zA-Z0-9_.\-@]{3,}/g;
  allMessagesFlat.forEach(({ msg }) => {
    const text = `${msg.subject || ""} ${msg.sender_display || ""} ${msg.body_plain || ""}`;
    const matches = text.match(tokenRx) || [];
    matches.forEach(tok => {
      const cmp = searchCaseSensitive ? tok : tok.toLowerCase();
      if (!q || cmp.includes(q)) {
        wordCounts[tok] = (wordCounts[tok] || 0) + 1;
      }
    });
  });

  const sortedWords = Object.entries(wordCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 80);

  const results = [];
  if (qRaw) {
    // 1. Search Messages
    allMessagesFlat.forEach(({ chain, msg }) => {
      const haySubj = searchCaseSensitive ? String(msg.subject || "") : String(msg.subject || "").toLowerCase();
      const haySender = searchCaseSensitive ? String(msg.sender_display || "") : String(msg.sender_display || "").toLowerCase();
      const hayBody = searchCaseSensitive ? String(msg.body_plain || "") : String(msg.body_plain || "").toLowerCase();
      const hayHdr = searchCaseSensitive ? String(msg.transport_headers || "") : String(msg.transport_headers || "").toLowerCase();

      if (haySubj.includes(q) || haySender.includes(q) || hayBody.includes(q) || hayHdr.includes(q)) {
        let snippet = msg.body_plain || "";
        const idx = hayBody.indexOf(q);
        if (idx !== -1) {
          const start = Math.max(0, idx - 50);
          const end = Math.min(snippet.length, idx + q.length + 90);
          snippet = (start > 0 ? "..." : "") + snippet.slice(start, end) + (end < snippet.length ? "..." : "");
        } else {
          snippet = snippet.slice(0, 140);
        }
        results.push({
          type: "Email Message",
          icon: "✉️",
          title: msg.subject || "(No Subject)",
          subtitle: `From: ${msg.sender_display} • Folder: ${msg.folder} • Chain Msg #${msg.chain_index}/${chain.msg_count}`,
          time: msg.time_local || msg.time_utc,
          snippet: snippet,
          chain_id: chain.chain_id,
          msg_id: msg.id
        });
      }
    });

    // 2. Search Attachments
    (rawData.attachments || []).forEach(att => {
      const hayFn = searchCaseSensitive ? String(att.fileName || "") : String(att.fileName || "").toLowerCase();
      const haySha = String(att.sha256 || "").toLowerCase();
      if (hayFn.includes(q) || haySha.includes(q.toLowerCase())) {
        results.push({
          type: "Attachment",
          icon: "📎",
          title: att.fileName,
          subtitle: `${att.category} (${formatBytes(att.size)}) • SHA256: ${(att.sha256 || "N/A").slice(0, 16)}...`,
          time: att.time_local || "",
          snippet: `Attached to Email: "${att.subject || ""}" from ${att.sender || ""}`,
          chain_id: att.chain_id,
          msg_id: att.msg_id,
          att_id: att.att_id
        });
      }
    });

    // 3. Search LevelDB Records
    (rawData.leveldb_records || []).forEach(lrec => {
      const hayK = searchCaseSensitive ? String(lrec.key || "") : String(lrec.key || "").toLowerCase();
      const hayV = searchCaseSensitive ? String(lrec.value || "") : String(lrec.value || "").toLowerCase();
      if (hayK.includes(q) || hayV.includes(q)) {
        results.push({
          type: "LevelDB Record",
          icon: "🗄️",
          title: `${lrec.table_name} :: ${lrec.key}`,
          subtitle: `Source: ${lrec.source_file} • Seq #${lrec.seq}`,
          time: lrec.timestamp || "",
          snippet: String(lrec.value || "").slice(0, 220)
        });
      }
    });
  }

  const wordPillsHtml = sortedWords.map(([w, cnt]) => `
    <span class="word-pill ${w.toLowerCase() === q.toLowerCase() ? 'active' : ''}" onclick="document.getElementById('globalSearchInput').value='${esc(w)}'; runGlobalSearch('${esc(w)}')">
      <span>${esc(w)}</span>
      <span style="opacity:0.75; font-size:10.5px;">(${cnt})</span>
    </span>
  `).join("");

  const resultsHtml = results.length === 0
    ? `<div class="empty-placeholder" style="height:260px;"><div class="icon">🔍</div><div>${qRaw ? `No matches found for "${esc(qRaw)}".` : "Type a keyword in the top search bar or click any token above to search."}</div></div>`
    : results.map(r => `
        <div class="search-result-card">
          <div style="display:flex; justify-content:space-between; align-items:center; gap:10px;">
            <span style="font-size:14px; font-weight:700;">${r.icon} [${esc(r.type)}] ${highlightTextSafe(r.title, qRaw)}</span>
            <span style="font-size:11.5px; color:var(--text-muted);">${esc(r.time)}</span>
          </div>
          <div style="font-size:12px; color:var(--text-muted);">${highlightTextSafe(r.subtitle, qRaw)}</div>
          <div style="font-size:13px; background:var(--bg-app); padding:9px 12px; border-radius:6px; border-left:3px solid var(--primary); font-family:Consolas,monospace; word-break:break-word;">
            ${highlightTextSafe(r.snippet, qRaw)}
          </div>
          <div style="display:flex; justify-content:flex-end; gap:8px;">
            ${r.att_id ? `<button class="btn-pane-action" onclick="openAttachmentPreview('${esc(r.att_id)}')">👁️ Preview File</button>` : ""}
            ${r.chain_id ? `<button class="btn-pane-action primary" onclick="switchTab('mail'); selectMailChain('${esc(r.chain_id)}', '${esc(r.msg_id || '')}');">📬 Jump to Mail Chain</button>` : ""}
          </div>
        </div>
      `).join("");

  container.innerHTML = `
    <div class="view-header">
      <h2>🔍 Global Forensic Search & Distinct Token Cloud</h2>
      <div style="font-size:13px; color:var(--text-muted);">
        ${qRaw ? `Showing <b>${results.length}</b> matches for "<b>${esc(qRaw)}</b>"` : `Indexed <b>${allMessagesFlat.length}</b> emails, <b>${(rawData.attachments || []).length}</b> attachments & <b>${(rawData.leveldb_records || []).length}</b> LevelDB records`}
      </div>
    </div>
    <div class="words-panel">
      <div style="font-size:13px; font-weight:700;">🔤 Top Matching Tokens & Identifiers (Click to Filter & Highlight):</div>
      <div class="words-cloud">${wordPillsHtml || '<span style="color:var(--text-muted); font-size:12px;">No tokens available.</span>'}</div>
    </div>
    <div style="display:flex; flex-direction:column; gap:10px;">
      ${resultsHtml}
    </div>
  `;
}

function renderAttachmentsView(filterText = "") {
  const container = document.getElementById("view-attachments");
  const atts = (rawData.attachments || []).filter(a => {
    if (!filterText) return true;
    const q = filterText.toLowerCase();
    return (
      String(a.fileName || "").toLowerCase().includes(q) ||
      String(a.category || "").toLowerCase().includes(q) ||
      String(a.subject || "").toLowerCase().includes(q) ||
      String(a.sender || "").toLowerCase().includes(q) ||
      String(a.sha256 || "").toLowerCase().includes(q)
    );
  });

  const rowsHtml = atts.map(att => {
    const icon = getAttachmentIcon(att.category, att.contentType, att.fileName);
    const fileUrl = resolveAttachmentUrl(att.rel_path);
    return `
      <tr>
        <td><b>${icon} ${esc(att.fileName)}</b>${att.isInline ? ` <span class="mini-badge att">CID</span>` : ""}</td>
        <td>${esc(att.category)}<br><span style="font-size:11px; color:var(--text-muted);">${esc(att.contentType)}</span></td>
        <td style="white-space:nowrap;"><b>${formatBytes(att.size)}</b><br><span style="font-size:10.5px; color:var(--text-muted);">${(att.size || 0).toLocaleString()} B</span></td>
        <td style="font-family:Consolas,monospace; font-size:11px; word-break:break-all;">${esc(att.sha256 || "N/A")}</td>
        <td><b>${esc(att.subject || "—")}</b><br><span style="font-size:11px; color:var(--text-muted);">From: ${esc(att.sender || "—")} • ${esc(att.time_local || "")}</span></td>
        <td style="white-space:nowrap;">
          <button class="btn-pane-action" onclick="openAttachmentPreview('${esc(att.att_id)}')">👁️ Preview</button>
          ${att.extracted && fileUrl ? `<a class="btn-pane-action primary" href="${esc(fileUrl)}" download="${esc(att.fileName)}">⬇️ Save</a>` : ""}
          ${att.chain_id ? `<button class="btn-pane-action" onclick="switchTab('mail'); selectMailChain('${esc(att.chain_id)}', '${esc(att.msg_id)}');">📬 Mail</button>` : ""}
        </td>
      </tr>
    `;
  }).join("");

  container.innerHTML = `
    <div class="view-header">
      <h2>📎 Extracted Email Attachments & Inline Media (${atts.length})</h2>
      <input type="text" class="search-filter-box" placeholder="Filter by filename, SHA-256, subject, sender..." value="${esc(filterText)}" oninput="renderAttachmentsView(this.value)">
    </div>
    <div class="data-table-wrapper">
      <table class="forensic-table">
        <thead>
          <tr>
            <th>Attachment Filename</th>
            <th>Type / MIME</th>
            <th>Exact Size</th>
            <th>SHA-256 Hash</th>
            <th>Parent Mail Chain & Sender</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          ${rowsHtml || `<tr><td colspan="6" style="text-align:center; padding:24px; color:var(--text-muted);">No attachments found.</td></tr>`}
        </tbody>
      </table>
    </div>
  `;
}

function renderCalendarView(filterText = "") {
  const container = document.getElementById("view-calendar");
  const list = (rawData.meetings || []).filter(m => {
    if (!filterText) return true;
    const q = filterText.toLowerCase();
    return (
      String(m.subject || "").toLowerCase().includes(q) ||
      String(m.organizer || "").toLowerCase().includes(q) ||
      String(m.attendees || "").toLowerCase().includes(q) ||
      String(m.location || "").toLowerCase().includes(q)
    );
  });

  const rowsHtml = list.map(m => `
    <tr>
      <td><b>📅 ${esc(m.subject)}</b>${m.body ? `<div style="font-size:11.5px; color:var(--text-muted); margin-top:4px;">${esc(m.body.slice(0, 180))}</div>` : ""}</td>
      <td><b>${esc(m.organizer || "—")}</b>${m.organizerEmail ? `<br><span style="font-size:11px; color:var(--text-muted);">${esc(m.organizerEmail)}</span>` : ""}</td>
      <td style="font-size:12px;">${esc(m.attendees || "—")}</td>
      <td style="white-space:nowrap;"><b>${esc(m.startTime || m.startTimeUtc || "—")}</b><br><span style="font-size:11px; color:var(--text-muted);">to ${esc(m.endTime || m.endTimeUtc || "—")}</span></td>
      <td>${esc(m.location || "—")}${m.joinUrl ? `<br><a href="${esc(m.joinUrl)}" target="_blank" style="color:var(--primary); font-size:11.5px; font-weight:600;">🔗 Join Meeting Link</a>` : ""}</td>
    </tr>
  `).join("");

  container.innerHTML = `
    <div class="view-header">
      <h2>📅 Outlook Calendar Appointments & Meetings (${list.length})</h2>
      <input type="text" class="search-filter-box" placeholder="Filter meetings by subject, organizer, attendee..." value="${esc(filterText)}" oninput="renderCalendarView(this.value)">
    </div>
    <div class="data-table-wrapper">
      <table class="forensic-table">
        <thead>
          <tr>
            <th>Meeting Subject & Notes</th>
            <th>Organizer</th>
            <th>Attendees</th>
            <th>Start / End Time</th>
            <th>Location / Link</th>
          </tr>
        </thead>
        <tbody>
          ${rowsHtml || `<tr><td colspan="5" style="text-align:center; padding:24px; color:var(--text-muted);">No calendar meetings found in this evidence source.</td></tr>`}
        </tbody>
      </table>
    </div>
  `;
}

function renderContactsView(filterText = "") {
  const container = document.getElementById("view-contacts");
  const list = (rawData.contacts || []).filter(c => {
    if (!filterText) return true;
    const q = filterText.toLowerCase();
    return (
      String(c.name || "").toLowerCase().includes(q) ||
      String(c.email || "").toLowerCase().includes(q) ||
      String(c.company || "").toLowerCase().includes(q) ||
      String(c.role || "").toLowerCase().includes(q)
    );
  });

  const rowsHtml = list.map(c => {
    const searchTarget = c.email || c.name;
    return `
      <tr>
        <td><b>👤 ${esc(c.name || "—")}</b></td>
        <td style="font-family:Consolas,monospace;">${esc(c.email || "—")}</td>
        <td>${esc(c.role || "—")}${c.department ? ` • ${esc(c.department)}` : ""}</td>
        <td>${esc(c.company || "—")}</td>
        <td><span class="mini-badge">📤 Sent: ${c.sent_count || 0}</span> <span class="mini-badge">📥 Recv: ${c.received_count || 0}</span></td>
        <td>
          <button class="btn-pane-action" onclick="switchTab('mail'); document.getElementById('chainFilterInput').value='${esc(searchTarget)}'; renderChainsList();">📬 View Mail Chains</button>
        </td>
      </tr>
    `;
  }).join("");

  container.innerHTML = `
    <div class="view-header">
      <h2>👥 Outlook Contacts & Email Correspondents (${list.length})</h2>
      <input type="text" class="search-filter-box" placeholder="Filter contacts by name, email, company..." value="${esc(filterText)}" oninput="renderContactsView(this.value)">
    </div>
    <div class="data-table-wrapper">
      <table class="forensic-table">
        <thead>
          <tr>
            <th>Display Name</th>
            <th>Email / SMTP Address</th>
            <th>Role & Department</th>
            <th>Company / Domain</th>
            <th>Mail Volume</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          ${rowsHtml || `<tr><td colspan="6" style="text-align:center; padding:24px; color:var(--text-muted);">No contacts found.</td></tr>`}
        </tbody>
      </table>
    </div>
  `;
}

function renderLevelDBView(filterText = "") {
  const container = document.getElementById("view-leveldb");
  const list = (rawData.leveldb_records || []).filter(r => {
    if (!filterText) return true;
    const q = filterText.toLowerCase();
    return (
      String(r.key || "").toLowerCase().includes(q) ||
      String(r.value || "").toLowerCase().includes(q) ||
      String(r.table_name || "").toLowerCase().includes(q) ||
      String(r.source_file || "").toLowerCase().includes(q)
    );
  });

  const rowsHtml = list.slice(0, 600).map(r => `
    <tr>
      <td style="font-family:Consolas,monospace; font-size:11.5px;"><b>${esc(r.table_name)}</b><br><span style="color:var(--text-muted);">${esc(r.source_file)}</span></td>
      <td style="font-family:Consolas,monospace; font-size:11.5px;">#${esc(r.seq)}<br><span class="mini-badge">${esc(r.record_type)}</span></td>
      <td style="font-family:Consolas,monospace; font-size:12px; font-weight:600; word-break:break-all; max-width:260px;">${highlightTextSafe(r.key, filterText)}</td>
      <td style="font-family:Consolas,monospace; font-size:11.5px; word-break:break-all; max-width:520px;">${highlightTextSafe(r.value, filterText)}</td>
      <td style="font-size:11.5px; white-space:nowrap;">${esc(r.timestamp || "—")}</td>
    </tr>
  `).join("");

  container.innerHTML = `
    <div class="view-header">
      <h2>🗄️ Decoded LevelDB, IndexedDB & New Outlook (Olk) Records (${list.length})</h2>
      <input type="text" class="search-filter-box" placeholder="Filter LevelDB keys, JSON values, tables..." value="${esc(filterText)}" oninput="renderLevelDBView(this.value)">
    </div>
    <div class="data-table-wrapper">
      <table class="forensic-table">
        <thead>
          <tr>
            <th>Table / Source File</th>
            <th>Seq / Type</th>
            <th>Decoded Record Key</th>
            <th>Decoded Value Payload (Unaltered)</th>
            <th>Timestamp</th>
          </tr>
        </thead>
        <tbody>
          ${rowsHtml || `<tr><td colspan="5" style="text-align:center; padding:24px; color:var(--text-muted);">No LevelDB records in this case.</td></tr>`}
        </tbody>
      </table>
    </div>
  `;
}

function renderOverviewView() {
  const container = document.getElementById("view-overview");
  const st = rawData.stats || {};

  const folderRows = (rawData.folders || []).map(f => `
    <tr>
      <td><b>${getFolderIcon(f.name)} ${esc(f.name)}</b></td>
      <td>${(f.total_chains || 0).toLocaleString()} chains</td>
      <td>${(f.total_messages || 0).toLocaleString()} messages</td>
      <td>${(f.unread_messages || 0).toLocaleString()} unread</td>
      <td><button class="btn-pane-action" onclick="switchTab('mail'); selectFolder('${esc(f.name)}');">📂 Open Folder</button></td>
    </tr>
  `).join("");

  const identRows = (st.account_identities || []).map(id => `
    <tr>
      <td><b>${esc(id.email)}</b></td>
      <td style="font-family:Consolas,monospace;">${esc(id.identity_id)}</td>
      <td style="font-family:Consolas,monospace; font-size:11.5px;">${esc(id.source)}</td>
    </tr>
  `).join("");

  container.innerHTML = `
    <div class="view-header">
      <h2>📊 Forensic Case Overview & Evidence Audit</h2>
      <div style="display:flex; gap:10px;">
        <button class="btn-pane-action primary" onclick="openCaseFolder()">📂 Open Case Folder (CSV Reports & Attachments)</button>
      </div>
    </div>

    <div class="stats-cards-grid">
      <div class="stat-card"><div class="stat-val">${(st.total_mail_chains || 0).toLocaleString()}</div><div class="stat-label">Reconstructed Mail Chains</div></div>
      <div class="stat-card"><div class="stat-val">${(st.total_messages || 0).toLocaleString()}</div><div class="stat-label">Decoded Email Messages</div></div>
      <div class="stat-card"><div class="stat-val">${(st.total_attachments || 0).toLocaleString()}</div><div class="stat-label">Extracted Attachments</div></div>
      <div class="stat-card"><div class="stat-val">${(st.total_folders || 0).toLocaleString()}</div><div class="stat-label">Mailbox Folders</div></div>
      <div class="stat-card"><div class="stat-val">${(st.total_meetings || 0).toLocaleString()}</div><div class="stat-label">Calendar Meetings</div></div>
      <div class="stat-card"><div class="stat-val">${(st.total_contacts || 0).toLocaleString()}</div><div class="stat-label">Contacts & Correspondents</div></div>
      <div class="stat-card"><div class="stat-val">${(st.total_leveldb_records || 0).toLocaleString()}</div><div class="stat-label">LevelDB / Olk Records</div></div>
    </div>

    <div class="data-table-wrapper">
      <table class="forensic-table">
        <thead><tr><th colspan="2">📋 Case Metadata & Custodian Scope</th></tr></thead>
        <tbody>
          <tr><td style="width:220px; font-weight:600;">Case Reference Name</td><td><b>${esc(st.case_name || "N/A")}</b></td></tr>
          <tr><td style="font-weight:600;">Custodian Profile & Email</td><td><b>${esc(st.user || "N/A")}</b> ${st.email ? `&lt;${esc(st.email)}&gt;` : ""} (${esc(st.tenant || "Microsoft Outlook")})</td></tr>
          <tr><td style="font-weight:600;">Ingested Evidence Source</td><td style="font-family:Consolas,monospace;">${esc(st.target_path || "N/A")}</td></tr>
          <tr><td style="font-weight:600;">Case Output Directory</td><td style="font-family:Consolas,monospace;">${esc(st.case_dir || "N/A")}</td></tr>
          <tr><td style="font-weight:600;">Extraction Timestamp</td><td>${esc(st.generated_at || "N/A")}</td></tr>
        </tbody>
      </table>
    </div>

    ${identRows ? `
    <div class="data-table-wrapper">
      <table class="forensic-table">
        <thead><tr><th>Configured New Outlook (Olk) Account Email</th><th>Identity Map ID / Hex</th><th>Source Artifact</th></tr></thead>
        <tbody>${identRows}</tbody>
      </table>
    </div>` : ""}

    <div class="data-table-wrapper">
      <table class="forensic-table">
        <thead><tr><th>Mailbox Folder</th><th>Mail Chains</th><th>Total Emails</th><th>Unread</th><th>Action</th></tr></thead>
        <tbody>${folderRows}</tbody>
      </table>
    </div>
  `;
}

function exportMailChainHtml(chainId) {
  const chain = (rawData.mail_chains || []).find(c => c.chain_id === chainId);
  if (!chain) return;

  const nowStr = new Date().toISOString().replace("T", " ").slice(0, 19) + " UTC";
  const msgsHtml = (chain.messages || []).map(m => {
    const toStr = (m.to_recipients || []).map(r => esc(r.display)).join("; ") || "—";
    const ccStr = (m.cc_recipients || []).map(r => esc(r.display)).join("; ");
    const bccStr = (m.bcc_recipients || []).map(r => esc(r.display)).join("; ");
    const attsStr = (m.attachments || []).map(a => `📎 ${esc(a.fileName)} (${formatBytes(a.size)}, SHA256: ${(a.sha256 || "N/A").slice(0, 16)}...)`).join(" &bull; ");
    const bodyHtml = m.body_html_clean ? m.body_html_clean : `<pre style="white-space:pre-wrap; font-family:inherit;">${esc(m.body_plain || "")}</pre>`;

    return `
      <div style="border:1px solid #d0d7de; border-radius:8px; margin-bottom:18px; background:#fff; overflow:hidden; page-break-inside:avoid;">
        <div style="background:#f6f8fa; padding:12px 16px; border-bottom:1px solid #d0d7de;">
          <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px;">
            <div style="font-size:14px; font-weight:700; color:#0f6cbd;">#${m.chain_index} of ${chain.msg_count} &bull; ${esc(m.sender_display)} <span style="font-size:11px; color:#555; font-weight:normal;">[${esc(m.folder)}]</span></div>
            <div style="font-size:12px; color:#555;"><b>Local:</b> ${esc(m.time_local)} | <b>UTC:</b> ${esc(m.time_utc)}</div>
          </div>
          <div style="font-size:12px; color:#333; margin-top:6px; line-height:1.5;">
            <div><b>Subject:</b> ${esc(m.subject)}</div>
            <div><b>To:</b> ${toStr}</div>
            ${ccStr ? `<div><b>Cc:</b> ${ccStr}</div>` : ""}
            ${bccStr ? `<div><b>Bcc:</b> ${bccStr}</div>` : ""}
            ${m.internet_message_id ? `<div style="font-family:Consolas,monospace; font-size:11px; color:#666;"><b>Message-ID:</b> ${esc(m.internet_message_id)} ${m.in_reply_to ? `| <b>In-Reply-To:</b> ${esc(m.in_reply_to)}` : ""}</div>` : ""}
            ${attsStr ? `<div style="margin-top:4px; padding:4px 8px; background:#ebf3fc; border-radius:4px; color:#0f6cbd; font-weight:600;">${attsStr}</div>` : ""}
          </div>
        </div>
        <div style="padding:16px; font-size:13.5px; line-height:1.6; color:#242424;">
          ${bodyHtml}
        </div>
      </div>
    `;
  }).join("");

  const fullHtml = `<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Outlook Mail Chain Export - ${esc(chain.subject)}</title>
<style>
body { font-family: "Segoe UI", sans-serif; background: #f3f4f6; color: #242424; padding: 24px; }
.wrapper { max-width: 960px; margin: 0 auto; }
.header { background: #0a2e4a; color: #fff; padding: 20px 24px; border-radius: 8px; margin-bottom: 20px; display:flex; justify-content:space-between; align-items:center; }
.btn-print { background: #0f6cbd; color: #fff; border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; font-weight: 600; }
@media print { .btn-print { display: none; } body { background: #fff; padding: 0; } }
</style>
</head>
<body>
<div class="wrapper">
  <div class="header">
    <div>
      <h2 style="margin:0 0 6px 0;">📬 ${esc(chain.subject)}</h2>
      <div style="font-size:12.5px; opacity:0.9;">Chain ID: ${esc(chain.chain_id)} &bull; ${chain.msg_count} Messages &bull; ${chain.attachment_count || 0} Attachments &bull; Exported: ${nowStr}</div>
    </div>
    <button class="btn-print" onclick="window.print()">🖨️ Print / Save PDF</button>
  </div>
  ${msgsHtml}
</div>
</body>
</html>`;

  const cleanSubj = String(chain.subject || "Mail_Chain").replace(/[^a-zA-Z0-9_\-\.]/g, "_").slice(0, 45);
  const fileName = `Outlook_Chain_${cleanSubj}.html`;

  const blob = new Blob([fullHtml], { type: "text/html;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.setAttribute("href", url);
  link.setAttribute("download", fileName);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  setTimeout(() => URL.revokeObjectURL(url), 1000);

  if (window.location.protocol.startsWith("http")) {
    const caseName = (rawData.stats && rawData.stats.case_name) || "";
    fetch("/api/export_chain_html", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        case_name: caseName,
        chain_title: cleanSubj,
        html_content: fullHtml
      })
    }).catch(() => {});
  }
}

function openCaseFolder() {
  const caseId = (rawData.stats && rawData.stats.case_name) || "";
  if (window.location.protocol === "file:") {
    fetch("http://127.0.0.1:5006/api/open_case_folder", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ case_id: caseId })
    }).catch(() => {
      alert("📂 Case Evidence Folder Location:\n\n" + ((rawData.stats && rawData.stats.case_dir) || ("cases/" + caseId)));
    });
    return;
  }
  fetch("/api/open_case_folder", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ case_id: caseId })
  }).then(r => r.json()).then(d => {
    if (d.status !== "success") alert("Case folder: " + (d.folder || "cases/" + caseId));
  }).catch(() => {
    alert("Case folder: " + ((rawData.stats && rawData.stats.case_dir) || "cases/" + caseId));
  });
}

function toggleTheme() {
  const body = document.body;
  const cur = body.getAttribute("data-theme");
  const next = cur === "dark" ? "light" : "dark";
  body.setAttribute("data-theme", next);
  document.getElementById("themeBtn").innerText = next === "dark" ? "☀️" : "🌙";
}

window.addEventListener("DOMContentLoaded", initViewer);
</script>
</body>
</html>
"""


DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Microsoft Outlook Forensic Case Suite</title>
<style>
:root {
  --primary: #0f6cbd;
  --primary-hover: #115ea3;
  --bg-app: #0f141c;
  --bg-card: #171f2c;
  --bg-input: #0c1017;
  --text-main: #f0f4f8;
  --text-muted: #9aa8bc;
  --border: #263348;
  --success: #107c41;
  --accent: #479ef5;
  --card-glow: 0 8px 24px rgba(0,0,0,0.45);
}
* { box-sizing: border-box; margin: 0; padding: 0; font-family: "Segoe UI", -apple-system, BlinkMacSystemFont, Roboto, sans-serif; }
body { background: var(--bg-app); color: var(--text-main); min-height: 100vh; display: flex; flex-direction: column; }

header {
  height: 60px;
  background: #0a1017;
  border-bottom: 1px solid var(--border);
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 24px;
}
.brand { display: flex; align-items: center; gap: 12px; font-weight: 700; font-size: 17px; letter-spacing: 0.3px; }
.brand svg { width: 26px; height: 26px; fill: var(--accent); }
.status-pill {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  background: #132a1c;
  color: #38c172;
  font-size: 11px;
  padding: 4px 10px;
  border-radius: 12px;
  border: 1px solid #1f472e;
}
.status-pill::before {
  content: "";
  display: inline-block;
  width: 7px;
  height: 7px;
  background: #38c172;
  border-radius: 50%;
}

.container { max-width: 1100px; width: 100%; margin: 24px auto; padding: 0 20px; display: flex; flex-direction: column; gap: 20px; }

.card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 22px;
  box-shadow: var(--card-glow);
}
.card h2 { font-size: 17px; margin-bottom: 6px; color: #fff; display: flex; align-items: center; gap: 8px; }
.card p { font-size: 13px; color: var(--text-muted); margin-bottom: 16px; line-height: 1.5; }

.text-input {
  width: 100%;
  background: var(--bg-input);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 10px 14px;
  color: var(--text-main);
  font-size: 13px;
  outline: none;
  transition: border-color 0.2s;
}
.text-input:focus { border-color: var(--accent); }

.btn {
  padding: 10px 18px;
  background: var(--primary);
  color: white;
  border: none;
  border-radius: 6px;
  cursor: pointer;
  font-weight: 600;
  font-size: 13px;
  display: inline-flex;
  align-items: center;
  gap: 8px;
  transition: all 0.15s;
  text-decoration: none;
}
.btn:hover { background: var(--primary-hover); transform: translateY(-1px); }
.btn-secondary { background: #212c3d; color: var(--text-main); border: 1px solid var(--border); }
.btn-secondary:hover { background: #2c3a50; }
.btn-success { background: #107c41; }
.btn-success:hover { background: #0e6c38; }

.console-box {
  background: #080b10;
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 14px;
  font-family: Consolas, monospace;
  font-size: 12px;
  color: #8ce99a;
  height: 185px;
  overflow-y: auto;
  line-height: 1.6;
  white-space: pre-wrap;
}
.progress-bar-container {
  height: 8px;
  background: #0c1017;
  border-radius: 4px;
  overflow: hidden;
  margin-bottom: 12px;
}
.progress-bar {
  height: 100%;
  width: 0%;
  background: var(--accent);
  transition: width 0.3s;
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(135px, 1fr));
  gap: 10px;
  margin: 16px 0;
}
.stat-box {
  background: var(--bg-input);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 14px;
  text-align: center;
}
.stat-num { font-size: 21px; font-weight: 700; color: var(--accent); }
.stat-lbl { font-size: 11px; color: var(--text-muted); margin-top: 4px; }

.case-banner {
  background: #112236;
  border: 1px solid #23476e;
  border-radius: 6px;
  padding: 10px 14px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 12px;
}
.case-badge {
  font-weight: 700;
  color: #7cc4fa;
  font-size: 13px;
  display: flex;
  align-items: center;
  gap: 6px;
}

table.cases-tbl {
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
  margin-top: 10px;
}
table.cases-tbl th {
  text-align: left;
  padding: 10px 12px;
  color: var(--text-muted);
  border-bottom: 1px solid var(--border);
  font-weight: 600;
}
table.cases-tbl td {
  padding: 12px;
  border-bottom: 1px solid #1e293b;
  vertical-align: middle;
}
table.cases-tbl tr:hover td { background: #1e293b; }
.badge-tag {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 4px;
  background: #172b42;
  color: #7cc4fa;
  font-size: 11px;
  font-weight: 600;
}
</style>
</head>
<body>

<header>
  <div class="brand">
    <svg viewBox="0 0 24 24"><path d="M12 2L2 7l10 5 10-5-10-5zm0 7.5l-6-3 6-3 6 3-6 3zm0 2.5l-10-5v10l10 5 10-5V7l-10 5z"/></svg>
    <span>Microsoft Outlook Forensic Suite</span>
  </div>
  <div style="display:flex; align-items:center; gap:12px;">
    <div class="status-pill">LevelDB + OST/PST Engine Ready</div>
    <button class="btn btn-secondary" onclick="openCasesRootFolder()" style="font-size:12px; padding:6px 12px;">📂 Cases Folder</button>
    <a href="/viewer" class="btn" style="font-size:12px; padding:6px 12px;">👁️ Active Case Viewer</a>
  </div>
</header>

<div class="container">
  <!-- Card 1: Start Investigation -->
  <div class="card">
    <h2>📬 Start Outlook Forensic Investigation</h2>
    <p>Select a New Outlook LevelDB/IndexedDB directory, an OST/PST file, or a folder containing MSG/EML evidence to decode mail chains, headers, and attachments into an isolated case folder.</p>

    <div style="display:flex; flex-wrap:wrap; gap:16px; margin-bottom:18px;">
      <div style="flex:1; min-width:320px;">
        <label style="display:block; font-size:13px; font-weight:600; color:#d0d8e8; margin-bottom:6px;">Target Evidence Path (LevelDB Folder, OST, PST, MSG, EML) <span style="color:#f87171;">*</span></label>
        <div style="display:flex; gap:8px;">
          <input type="text" id="targetPathInput" class="text-input" value="%localappdata%\Microsoft\Olk" placeholder="e.g. %localappdata%\Microsoft\Olk or C:\Evidence\mailbox.pst" style="flex:1; font-size:13.5px; padding:11px 14px; font-family:Consolas, monospace;">
          <button id="browseFolderBtn" class="btn btn-secondary" onclick="browseFolderOnly()" style="padding:11px 14px; white-space:nowrap;">📁 Folder...</button>
          <button id="browseFileBtn" class="btn btn-secondary" onclick="browseFileOnly()" style="padding:11px 14px; white-space:nowrap;">📄 OST/PST File...</button>
        </div>
      </div>
      <div style="width:270px;">
        <label style="display:block; font-size:13px; font-weight:600; color:#d0d8e8; margin-bottom:6px;">Case Reference Name <span style="color:#f87171;">*</span></label>
        <input type="text" id="caseNameInput" class="text-input" value="Outlook_Investigation_1" placeholder="Enter Case Reference Name..." style="font-size:13.5px; padding:11px 14px;">
      </div>
    </div>

    <div style="margin-bottom:20px;">
      <button id="startParseBtn" class="btn" onclick="startExtractionFromInput()" style="font-size:15px; padding:12px 28px; border-radius:8px; font-weight:700; box-shadow:0 4px 14px rgba(15,108,189,0.45);">
        <span>🚀</span>
        <span>Start Outlook Forensic Extraction</span>
      </button>
    </div>

    <div style="background:#0c121b; border:1px solid #1e2d42; border-radius:8px; padding:16px 18px;">
      <div style="font-weight:700; font-size:13px; color:#7cc4fa; margin-bottom:12px;">📌 Standard Microsoft Outlook Artifact Locations:</div>
      <div style="display:flex; flex-direction:column; gap:10px;">
        <div style="background:#131c29; border-left:3px solid #0f6cbd; padding:10px 14px; border-radius:0 6px 6px 0; display:flex; justify-content:space-between; align-items:center; gap:12px; flex-wrap:wrap;">
          <div>
            <div style="font-weight:600; font-size:12px; color:#e2e8f0;">1. New Outlook for Windows (Monarch / Olk LevelDB & IndexedDB):</div>
            <code style="font-family:Consolas,monospace; font-size:11.5px; color:#7fdbca;">%localappdata%\Microsoft\Olk</code>
          </div>
          <button class="btn btn-secondary" onclick="copyPathText(this, '%localappdata%\\Microsoft\\Olk')" style="font-size:11px; padding:4px 10px;">📋 Select Path</button>
        </div>
        <div style="background:#131c29; border-left:3px solid #107c41; padding:10px 14px; border-radius:0 6px 6px 0; display:flex; justify-content:space-between; align-items:center; gap:12px; flex-wrap:wrap;">
          <div>
            <div style="font-weight:600; font-size:12px; color:#e2e8f0;">2. Classic Outlook OST Offline Cache Folder:</div>
            <code style="font-family:Consolas,monospace; font-size:11.5px; color:#7fdbca;">%localappdata%\Microsoft\Outlook</code>
          </div>
          <button class="btn btn-secondary" onclick="copyPathText(this, '%localappdata%\\Microsoft\\Outlook')" style="font-size:11px; padding:4px 10px;">📋 Select Path</button>
        </div>
        <div style="background:#131c29; border-left:3px solid #d97706; padding:10px 14px; border-radius:0 6px 6px 0; display:flex; justify-content:space-between; align-items:center; gap:12px; flex-wrap:wrap;">
          <div>
            <div style="font-weight:600; font-size:12px; color:#e2e8f0;">3. Classic Outlook PST Archives & Exported MSG / EML Folders:</div>
            <code style="font-family:Consolas,monospace; font-size:11.5px; color:#7fdbca;">C:\Users\{{ current_user }}\Documents\Outlook Files</code>
          </div>
          <button class="btn btn-secondary" onclick="copyPathText(this, 'C:\\Users\\{{ current_user }}\\Documents\\Outlook Files')" style="font-size:11px; padding:4px 10px;">📋 Select Path</button>
        </div>
      </div>
    </div>
  </div>

  <!-- Card 2: Live Progress & Results -->
  <div class="card">
    <h2>⚙️ Live Execution Console & Extraction Status</h2>
    <div class="progress-bar-container">
      <div class="progress-bar" id="progressBar"></div>
    </div>
    <div class="console-box" id="consoleBox">[System] Ready. Select an Outlook LevelDB folder or OST/PST/MSG/EML source to begin forensic decoding.</div>

    <div id="resultsPanel" style="display:none; margin-top:18px;">
      <div class="case-banner">
        <div class="case-badge">📁 Active Case: <span id="caseNameBadge" style="color:#fff;">Case</span></div>
        <span id="casePathDisplay" style="font-size:12px; color:var(--text-muted); font-family:Consolas, monospace;">cases/</span>
      </div>

      <div class="stats-grid">
        <div class="stat-box"><div class="stat-num" id="statChains">0</div><div class="stat-lbl">Mail Chains</div></div>
        <div class="stat-box"><div class="stat-num" id="statMsgs">0</div><div class="stat-lbl">Emails Decoded</div></div>
        <div class="stat-box"><div class="stat-num" id="statAtts">0</div><div class="stat-lbl">Attachments</div></div>
        <div class="stat-box"><div class="stat-num" id="statFolders">0</div><div class="stat-lbl">Mail Folders</div></div>
        <div class="stat-box"><div class="stat-num" id="statMeetings">0</div><div class="stat-lbl">Calendar Events</div></div>
        <div class="stat-box"><div class="stat-num" id="statContacts">0</div><div class="stat-lbl">Contacts</div></div>
        <div class="stat-box"><div class="stat-num" id="statLdb">0</div><div class="stat-lbl">LevelDB Records</div></div>
      </div>

      <div style="display:flex; flex-wrap:wrap; gap:12px; margin-top:14px; justify-content:center;">
        <a id="btnOpenViewer" href="/viewer" class="btn btn-success" style="padding:11px 24px; font-size:14px;">👁️ Open Outlook Forensic Viewer</a>
        <button class="btn btn-secondary" onclick="openCurrentCaseFolder()" style="padding:11px 22px; font-size:14px;">📂 Open Case Folder in Explorer</button>
      </div>
    </div>
  </div>

  <!-- Card 3: Investigated Cases Repository -->
  <div class="card">
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
      <h2>📁 Investigated Outlook Cases Repository</h2>
      <button class="btn btn-secondary" onclick="loadCases()" style="font-size:12px; padding:5px 12px;">🔄 Refresh</button>
    </div>
    <p>Each case folder contains its standalone Outlook HTML viewer, reconstructed mail chains CSV, full messages CSV, SHA-256 attachment manifest, and extracted attachments.</p>
    <div style="overflow-x:auto;">
      <table class="cases-tbl">
        <thead>
          <tr>
            <th>Case Reference</th>
            <th>Custodian / Mailbox</th>
            <th>Date Ingested</th>
            <th>Mail Chains</th>
            <th>Emails</th>
            <th>Attachments</th>
            <th style="text-align:center;">Actions</th>
          </tr>
        </thead>
        <tbody id="casesTableBody"></tbody>
      </table>
    </div>
  </div>
</div>

<script>
let pollInterval = null;
let currentActiveCase = "";

function copyPathText(btn, text) {
  const inp = document.getElementById("targetPathInput");
  if (inp) inp.value = text;
  const orig = btn.innerText;
  btn.innerText = "✅ Selected!";
  setTimeout(() => { btn.innerText = orig; }, 1200);
}

async function browseFolderOnly() {
  const btn = document.getElementById("browseFolderBtn");
  btn.innerText = "⏳...";
  btn.disabled = true;
  try {
    const res = await fetch("/api/pick_folder_path", { method: "POST" });
    const data = await res.json();
    if (data.path) document.getElementById("targetPathInput").value = data.path;
  } catch (e) {}
  btn.innerText = "📁 Folder...";
  btn.disabled = false;
}

async function browseFileOnly() {
  const btn = document.getElementById("browseFileBtn");
  btn.innerText = "⏳...";
  btn.disabled = true;
  try {
    const res = await fetch("/api/pick_file_path", { method: "POST" });
    const data = await res.json();
    if (data.path) document.getElementById("targetPathInput").value = data.path;
  } catch (e) {}
  btn.innerText = "📄 OST/PST File...";
  btn.disabled = false;
}

async function startExtractionFromInput() {
  const pathInput = document.getElementById("targetPathInput");
  const caseInput = document.getElementById("caseNameInput");
  const targetPath = (pathInput.value || "").trim();
  const cname = (caseInput.value || "").trim();

  if (!targetPath) {
    alert("⚠️ Please enter or browse for the Target Evidence Path.");
    pathInput.focus();
    return;
  }
  if (!cname) {
    alert("⚠️ Please enter a Case Reference Name.");
    caseInput.focus();
    return;
  }

  const btn = document.getElementById("startParseBtn");
  const origHtml = btn.innerHTML;
  btn.innerHTML = "<span>⏳</span><span>Starting Extraction...</span>";
  btn.disabled = true;

  try {
    const res = await fetch("/api/parse_path", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path: targetPath, case_name: cname })
    });
    const data = await res.json();
    btn.innerHTML = origHtml;
    btn.disabled = false;

    if (data.status === "started") {
      document.getElementById("resultsPanel").style.display = "none";
      document.getElementById("consoleBox").innerText = `[System] Target path: ${targetPath}\n[System] Case Reference: ${cname}\n[System] Initializing Outlook Forensic Engine...\n`;
      startPolling();
    } else {
      alert("Error: " + (data.message || "Failed to start extraction."));
    }
  } catch (err) {
    btn.innerHTML = origHtml;
    btn.disabled = false;
    alert("Extraction error: " + err);
  }
}

let lastLogLen = 0;
function startPolling() {
  if (pollInterval) clearInterval(pollInterval);
  lastLogLen = 0;
  pollInterval = setInterval(() => {
    fetch("/api/progress")
      .then(r => r.json())
      .then(data => {
        document.getElementById("progressBar").style.width = (data.progress || 0) + "%";
        if (data.logs && data.logs.length > lastLogLen) {
          const cbox = document.getElementById("consoleBox");
          cbox.innerText = data.logs.join("\n");
          cbox.scrollTop = cbox.scrollHeight;
          lastLogLen = data.logs.length;
        }
        if (data.completed) {
          clearInterval(pollInterval);
          showCompletedResults(data);
          loadCases();
        } else if (data.error) {
          clearInterval(pollInterval);
          alert("Error during extraction: " + data.error);
        }
      })
      .catch(() => {});
  }, 800);
}

function showCompletedResults(data) {
  const stats = data.stats || {};
  document.getElementById("resultsPanel").style.display = "block";
  currentActiveCase = data.active_case || stats.case_name || "";
  document.getElementById("caseNameBadge").innerText = currentActiveCase || "Completed Case";
  document.getElementById("casePathDisplay").innerText = data.case_dir || stats.case_dir || ("cases/" + currentActiveCase);
  document.getElementById("btnOpenViewer").href = currentActiveCase ? `/cases/${encodeURIComponent(currentActiveCase)}/viewer` : "/viewer";

  document.getElementById("statChains").innerText = (stats.total_mail_chains || 0).toLocaleString();
  document.getElementById("statMsgs").innerText = (stats.total_messages || 0).toLocaleString();
  document.getElementById("statAtts").innerText = (stats.total_attachments || 0).toLocaleString();
  document.getElementById("statFolders").innerText = (stats.total_folders || 0).toLocaleString();
  document.getElementById("statMeetings").innerText = (stats.total_meetings || 0).toLocaleString();
  document.getElementById("statContacts").innerText = (stats.total_contacts || 0).toLocaleString();
  document.getElementById("statLdb").innerText = (stats.total_leveldb_records || 0).toLocaleString();
}

function openCurrentCaseFolder() {
  fetch("/api/open_case_folder", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ case_id: currentActiveCase })
  }).catch(() => {});
}

function openCasesRootFolder() {
  fetch("/api/open_case_folder", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ open_root: true })
  }).catch(() => {});
}

function openSpecificCaseFolder(caseId) {
  fetch("/api/open_case_folder", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ case_id: caseId })
  }).catch(() => {});
}

function loadCases() {
  fetch("/api/cases")
    .then(r => r.json())
    .then(cases => {
      const tbody = document.getElementById("casesTableBody");
      if (!cases || cases.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color:var(--text-muted); padding:20px;">No Outlook forensic cases investigated yet. Select a folder or OST/PST file above to begin.</td></tr>`;
        return;
      }
      tbody.innerHTML = cases.map(c => `
        <tr>
          <td><b>${c.case_id}</b></td>
          <td>${c.target_user}</td>
          <td style="font-size:12px; color:var(--text-muted);">${c.created_at}</td>
          <td><span class="badge-tag">${(c.stats.mail_chains || 0).toLocaleString()} chains</span></td>
          <td>${(c.stats.messages || 0).toLocaleString()} msgs</td>
          <td>${(c.stats.attachments || 0).toLocaleString()} files</td>
          <td style="text-align:center; white-space:nowrap;">
            <a href="/cases/${encodeURIComponent(c.case_id)}/viewer" class="btn btn-secondary" style="font-size:12px; padding:4px 10px; margin-right:6px;">👁️ Open Viewer</a>
            <button class="btn btn-secondary" onclick="openSpecificCaseFolder('${c.case_id}')" style="font-size:12px; padding:4px 8px;">📂 Folder</button>
          </td>
        </tr>
      `).join("");
    })
    .catch(() => {});
}

window.addEventListener("DOMContentLoaded", () => {
  loadCases();
  fetch("/api/progress")
    .then(r => r.json())
    .then(data => {
      if (data.completed || (data.stats && (data.stats.total_messages !== undefined))) {
        showCompletedResults(data);
        document.getElementById("progressBar").style.width = "100%";
        if (data.logs && data.logs.length > 0) {
          document.getElementById("consoleBox").innerText = data.logs.join("\n");
        }
      }
    })
    .catch(() => {});
});
</script>
</body>
</html>
"""

_case_data_cache = {}

def load_case_dataset(case_name):
    if not case_name:
        case_name = parsing_status.get("active_case") or get_latest_case()
    if not case_name:
        return None, "No case available"
    case_dir = os.path.join(CASES_DIR, case_name)
    viewer_path = os.path.join(case_dir, "Outlook_Forensic_Viewer.html")
    if not os.path.exists(viewer_path):
        return None, f"Case viewer not found for {case_name}"
    try:
        mtime = os.path.getmtime(viewer_path)
        cached = _case_data_cache.get(case_name)
        if cached and cached.get("mtime") == mtime:
            return cached["data"], None
        with open(viewer_path, "r", encoding="utf-8", errors="ignore") as f:
            html_text = f.read()
        marker = "window.OUTLOOK_FORENSIC_DATA = "
        m = html_text.find(marker)
        if m == -1:
            return None, "Forensic dataset not found in viewer"
        end = html_text.find(";\n</script>", m)
        raw_json = html_text[m + len(marker):end].replace("<\\/script>", "</script>").replace("<\\/SCRIPT>", "</SCRIPT>")
        case_data = json.loads(raw_json)
        _case_data_cache[case_name] = {"mtime": mtime, "data": case_data}
        return case_data, None
    except Exception as e:
        return None, str(e)

@app.route("/")
def index():
    return render_template_string(DASHBOARD_HTML, current_user=os.environ.get("USERNAME", "User"))

@app.route("/api/cases")
def api_cases():
    cases_list = []
    if os.path.exists(CASES_DIR):
        for cname in sorted(os.listdir(CASES_DIR), reverse=True):
            cdir = os.path.join(CASES_DIR, cname)
            if not os.path.isdir(cdir):
                continue
            viewer_file = os.path.join(cdir, "Outlook_Forensic_Viewer.html")
            stats = {"mail_chains": 0, "messages": 0, "attachments": 0, "leveldb_records": 0}
            target_user = "Outlook Account"
            created_at = datetime.datetime.fromtimestamp(os.path.getmtime(cdir)).strftime("%Y-%m-%d %H:%M:%S")

            if os.path.exists(viewer_file):
                try:
                    with open(viewer_file, "r", encoding="utf-8", errors="ignore") as vf:
                        head = vf.read(200000)
                    m_stats = re.search(r'"stats":\s*({.*?})\s*,\s*"folders"', head, re.DOTALL)
                    if m_stats:
                        st = json.loads(m_stats.group(1))
                        stats = {
                            "mail_chains": st.get("total_mail_chains", 0),
                            "messages": st.get("total_messages", 0),
                            "attachments": st.get("total_attachments", 0),
                            "meetings": st.get("total_meetings", 0),
                            "contacts": st.get("total_contacts", 0),
                            "leveldb_records": st.get("total_leveldb_records", 0)
                        }
                        u = st.get("user") or "Outlook Account"
                        em = st.get("email") or ""
                        target_user = f"{u} <{em}>" if (em and em not in u) else u
                except Exception:
                    pass

            cases_list.append({
                "case_id": cname,
                "case_name": f"Investigation - {cname}",
                "target_user": target_user,
                "created_at": created_at,
                "case_directory": cdir,
                "stats": stats
            })
    return jsonify(cases_list)

@app.route("/api/search", methods=["POST"])
def api_search():
    data = request.get_json() or {}
    query = (data.get("query") or "").strip()
    case_name = (data.get("case_name") or "").strip()
    if not query:
        return jsonify({"status": "error", "message": "Query string is required"}), 400

    case_data, err = load_case_dataset(case_name)
    if err or not case_data:
        return jsonify({"status": "error", "message": err or "Case not found"}), 404

    t0 = time.time()
    q = query.lower()
    results = []

    for chain in case_data.get("mail_chains", []):
        cid = chain.get("chain_id", "")
        csubj = chain.get("subject", "")
        for msg in chain.get("messages", []):
            plain = str(msg.get("body_plain") or "")
            subj = str(msg.get("subject") or "")
            sender = str(msg.get("sender_display") or msg.get("sender_name") or "")
            hdrs = str(msg.get("transport_headers") or "")
            if q in plain.lower() or q in subj.lower() or q in sender.lower() or q in hdrs.lower():
                idx = plain.lower().find(q)
                if idx != -1:
                    s_pos = max(0, idx - 40)
                    e_pos = min(len(plain), idx + len(q) + 70)
                    snippet = ("..." if s_pos > 0 else "") + plain[s_pos:e_pos] + ("..." if e_pos < len(plain) else "")
                else:
                    snippet = plain[:120] or subj
                results.append({
                    "category": "Message",
                    "chain_id": cid,
                    "chain_subject": csubj,
                    "msg_id": msg.get("id", ""),
                    "folder": msg.get("folder", "Inbox"),
                    "sender": sender,
                    "time": msg.get("time_local") or msg.get("time_utc") or "",
                    "snippet": snippet,
                    "attachments": len(msg.get("attachments", []))
                })

    for att in case_data.get("attachments", []):
        fn = str(att.get("fileName") or "")
        sha = str(att.get("sha256") or "")
        if q in fn.lower() or q in sha.lower():
            results.append({
                "category": "Attachment",
                "chain_id": att.get("chain_id", ""),
                "chain_subject": att.get("subject", ""),
                "msg_id": att.get("msg_id", ""),
                "att_id": att.get("att_id", ""),
                "sender": att.get("sender", ""),
                "time": att.get("time_local", ""),
                "snippet": f"Attachment: {fn} ({att.get('category')}, {att.get('size', 0)} bytes, SHA256: {sha[:16]}...)"
            })

    for lrec in case_data.get("leveldb_records", []):
        k = str(lrec.get("key") or "")
        v = str(lrec.get("value") or "")
        if q in k.lower() or q in v.lower():
            results.append({
                "category": "LevelDB",
                "chain_id": "",
                "chain_subject": lrec.get("table_name", "LevelDB"),
                "msg_id": str(lrec.get("seq") or ""),
                "sender": lrec.get("source_file", ""),
                "time": lrec.get("timestamp", ""),
                "snippet": f"{k}: {v[:160]}"
            })

    elapsed = round((time.time() - t0) * 1000, 1)
    return jsonify({
        "status": "success",
        "case_name": case_name or parsing_status.get("active_case"),
        "query": query,
        "total": len(results),
        "time_ms": elapsed,
        "results": results
    })

@app.route("/api/open_case_folder", methods=["POST"])
def api_open_case_folder():
    data = request.get_json() or {}
    case_id = (data.get("case_id") or "").strip()
    open_root = data.get("open_root", False)
    if open_root:
        target = CASES_DIR
    elif case_id:
        target = os.path.join(CASES_DIR, case_id)
    elif parsing_status.get("active_case"):
        target = os.path.join(CASES_DIR, parsing_status["active_case"])
    elif get_latest_case():
        target = os.path.join(CASES_DIR, get_latest_case())
    else:
        target = CASES_DIR
    if not os.path.exists(target):
        target = TOOL_DIR
    try:
        os.startfile(target)
        return jsonify({"status": "success", "folder": target})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e), "folder": target}), 500

@app.route("/api/export_chain_html", methods=["POST"])
@app.route("/api/export_chat_html", methods=["POST"])
def api_export_chain_html():
    data = request.get_json() or {}
    case_name = (data.get("case_name") or parsing_status.get("active_case") or get_latest_case() or "").strip()
    chain_title = (data.get("chain_title") or data.get("chat_title") or "Mail_Chain").strip()
    html_content = data.get("html_content") or ""
    if not html_content:
        return jsonify({"status": "error", "message": "No HTML content provided"}), 400

    clean_title = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', chain_title)[:45]
    out_name = f"Outlook_Chain_{clean_title}.html"
    case_dir = os.path.join(CASES_DIR, case_name) if case_name else CASES_DIR
    os.makedirs(case_dir, exist_ok=True)
    out_path = os.path.join(case_dir, out_name)
    try:
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        return jsonify({"status": "success", "file_name": out_name, "path": out_path})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/cases/<case_id>/viewer")
def case_viewer(case_id):
    cdir = os.path.join(CASES_DIR, case_id)
    p = os.path.join(cdir, "Outlook_Forensic_Viewer.html")
    if os.path.exists(p):
        return send_file(p, mimetype="text/html")
    return render_template_string(VIEWER_TEMPLATE_HTML)

@app.route("/cases/<case_id>/outlook_attachments/<path:filename>")
def case_attachments(case_id, filename):
    clean_fn = filename.replace("/", os.sep)
    p = os.path.join(CASES_DIR, case_id, "outlook_attachments", clean_fn)
    if os.path.exists(p):
        return send_file(p)
    return "Attachment not found", 404

@app.route("/cases/<case_id>/report")
def case_report(case_id):
    p = os.path.join(CASES_DIR, case_id, "Case_Audit_Summary.txt")
    if os.path.exists(p):
        return send_file(p, mimetype="text/plain")
    return "Report not found", 404

@app.route("/viewer")
def viewer():
    cur = parsing_status.get("active_case") or get_latest_case()
    if cur:
        p = os.path.join(CASES_DIR, cur, "Outlook_Forensic_Viewer.html")
        if os.path.exists(p):
            return send_file(p, mimetype="text/html")
    return render_template_string(VIEWER_TEMPLATE_HTML)

@app.route("/outlook_attachments/<path:filename>")
def serve_attachment(filename):
    clean_fn = filename.replace("/", os.sep)
    cur = parsing_status.get("active_case") or get_latest_case()
    if cur:
        p = os.path.join(CASES_DIR, cur, "outlook_attachments", clean_fn)
        if os.path.exists(p):
            return send_file(p)
    return "Attachment not found", 404

@app.route("/download/attachments_zip")
def download_attachments_zip():
    cur = parsing_status.get("active_case") or get_latest_case()
    if not cur:
        return "No active case", 404
    cdir = os.path.join(CASES_DIR, cur)
    att_dir = os.path.join(cdir, "outlook_attachments")
    if not os.path.exists(att_dir):
        return "No attachments folder found", 404
    zip_path = os.path.join(cdir, "Outlook_Extracted_Attachments.zip")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for r, _, files in os.walk(att_dir):
            for f in files:
                fp = os.path.join(r, f)
                zf.write(fp, os.path.relpath(fp, att_dir))
    return send_file(zip_path, as_attachment=True, download_name=f"{cur}_Attachments.zip")

@app.route("/api/parse_path", methods=["POST"])
def api_parse_path():
    data = request.get_json() or {}
    raw_path = (data.get("path") or "").strip()
    case_name = (data.get("case_name") or "").strip()
    expanded_path = os.path.expandvars(os.path.expanduser(raw_path))
    if not expanded_path or not os.path.exists(expanded_path):
        return jsonify({"status": "error", "message": f"Path does not exist: {expanded_path}"}), 400

    def task():
        parsing_status["running"] = True
        parsing_status["completed"] = False
        parsing_status["error"] = None
        parsing_status["progress"] = 0
        parsing_status["logs"] = []
        try:
            engine = OutlookForensicEngine(expanded_path, case_name=case_name)
            engine.run_pipeline()
            parsing_status["completed"] = True
        except Exception as e:
            parsing_status["error"] = str(e)
            log_progress(f"Fatal error during execution: {e}")
        finally:
            parsing_status["running"] = False

    t = threading.Thread(target=task, daemon=True)
    t.start()
    return jsonify({"status": "started", "path": expanded_path, "case_name": case_name})

@app.route("/api/select_folder", methods=["POST"])
def api_select_folder():
    data = request.get_json() or {}
    case_name = (data.get("case_name") or "").strip()
    if not case_name:
        return jsonify({"status": "error", "message": "Case Reference Name is required"}), 400
    chosen_path = native_folder_picker()
    if not chosen_path:
        return jsonify({"status": "cancelled", "message": "Folder selection cancelled"})
    if not os.path.exists(chosen_path):
        return jsonify({"status": "error", "message": f"Path does not exist: {chosen_path}"}), 400

    def task():
        parsing_status["running"] = True
        parsing_status["completed"] = False
        parsing_status["error"] = None
        parsing_status["progress"] = 0
        parsing_status["logs"] = []
        try:
            engine = OutlookForensicEngine(chosen_path, case_name=case_name)
            engine.run_pipeline()
            parsing_status["completed"] = True
        except Exception as e:
            parsing_status["error"] = str(e)
            log_progress(f"Fatal error during execution: {e}")
        finally:
            parsing_status["running"] = False

    t = threading.Thread(target=task, daemon=True)
    t.start()
    return jsonify({"status": "started", "path": chosen_path, "case_name": case_name})

@app.route("/api/pick_folder_path", methods=["POST"])
def api_pick_folder_path():
    chosen_path = native_folder_picker()
    return jsonify({"path": chosen_path or ""})

@app.route("/api/pick_file_path", methods=["POST"])
def api_pick_file_path():
    chosen_path = native_file_picker()
    return jsonify({"path": chosen_path or ""})

@app.route("/api/progress")
def api_progress():
    return jsonify(parsing_status)

def launch_desktop_window(url):
    browser_candidates = [
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        shutil.which("msedge"),
        shutil.which("chrome")
    ]
    for b_path in browser_candidates:
        if b_path and os.path.exists(b_path):
            try:
                subprocess.Popen([b_path, f"--app={url}"])
                return True
            except Exception:
                pass
    webbrowser.open(url)
    return True

def run_flask_server(port):
    log = logging.getLogger("werkzeug")
    log.setLevel(logging.ERROR)
    app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False, threaded=True)

def find_available_port(start_port=5006):
    import socket
    for p in range(start_port, start_port + 50):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(("127.0.0.1", p)) != 0:
                return p
    return start_port

def main():
    # Direct CLI extraction if target path is supplied as argument
    # Usage: python outlook_forensic_tool.py <path_to_leveldb_or_pst_or_ost> [--case <CaseName>] [--no-browser]
    if len(sys.argv) > 1 and not sys.argv[1].startswith("-"):
        cli_target = os.path.expandvars(os.path.expanduser(sys.argv[1].strip()))
        cli_case = None
        no_browser = "--no-browser" in sys.argv
        for i in range(2, len(sys.argv)):
            if sys.argv[i].lower() in ("--case", "-c", "--name", "-name") and i + 1 < len(sys.argv):
                cli_case = sys.argv[i + 1].strip()
                break
            elif not sys.argv[i].startswith("-") and not cli_case:
                cli_case = sys.argv[i].strip()
        if os.path.exists(cli_target):
            print("=" * 80)
            print("MICROSOFT OUTLOOK FORENSIC SUITE - DIRECT CLI PARSER")
            print(f"Target Evidence Path : {cli_target}")
            print("=" * 80)
            engine = OutlookForensicEngine(cli_target, case_name=cli_case)
            engine.run_pipeline()
            viewer_path = os.path.join(engine.case_dir, "Outlook_Forensic_Viewer.html")
            print("\n" + "=" * 80)
            print(f"[Done] Case successfully exported to : {engine.case_dir}")
            print(f"[Viewer] Standalone Outlook UI Report: {viewer_path}")
            print("=" * 80)
            if not no_browser:
                try:
                    webbrowser.open(viewer_path)
                except Exception:
                    pass
            return
        else:
            print(f"[Error] Specified evidence path does not exist: {cli_target}")
            sys.exit(1)

    import socket
    port = find_available_port(5006)
    url = f"http://127.0.0.1:{port}"
    print("=" * 80)
    print("MICROSOFT OUTLOOK FORENSIC SUITE - DESKTOP APPLICATION")
    print(f"Tool directory   : {TOOL_DIR}")
    print(f"Cases directory  : {CASES_DIR}")
    print(f"Server endpoint  : {url}")
    print("Starting desktop application...")
    print("=" * 80)

    flask_thread = threading.Thread(target=run_flask_server, args=(port,), daemon=True)
    flask_thread.start()

    for _ in range(60):
        time.sleep(0.05)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                break

    if "--no-browser" not in sys.argv:
        launch_desktop_window(url)
    print(f"[Ready] Application running at {url}")
    print("Press Ctrl+C in this terminal window to stop the server.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping Microsoft Outlook Forensic Suite...")
        sys.exit(0)

if __name__ == "__main__":
    main()
