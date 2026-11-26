"""Attachments: what they are, what they claim to be, and what they could do.

- Executables and scripts run code the moment they're opened.
- "invoice.pdf.exe" relies on Windows hiding the last extension.
- A right-to-left override character reverses the end of a name, so
  "invoice<RLO>fdp.exe" is displayed as "invoiceexe.pdf".
- Archives and disk images (zip, iso) carry files past scanners, especially
  when password-protected.
- Office files can carry VBA macros, which run code when enabled.
- HTML attachments open in the browser, where script can build a file
  locally and "download" it ("HTML smuggling"), so the dangerous file never
  passes the mail filter as an attachment.
- A file whose bytes don't match its name or declared type is disguised.

Nothing here opens or runs an attachment. Macros are found with oletools,
which reads VBA code without executing it. It runs in a worker thread; a
hostile file that made it spin would keep that thread busy past the check
timeout, so moving attachment parsing into the sandbox worker is on the
roadmap (see the threat model).
"""

import asyncio
import io
import logging
import re
import zipfile
from dataclasses import dataclass, field
from typing import Protocol

from phishlens.email.parse import Attachment, ParsedEmail
from phishlens.findings import BodyEvidence, CheckContext, Finding, Severity

logger = logging.getLogger(__name__)

EXECUTABLE = frozenset(
    [
        "exe",
        "scr",
        "com",
        "pif",
        "bat",
        "cmd",
        "ps1",
        "psm1",
        "vbs",
        "vbe",
        "js",
        "jse",
        "wsf",
        "wsh",
        "hta",
        "msi",
        "msp",
        "lnk",
        "jar",
        "reg",
        "cpl",
        "dll",
        "appx",
        "msix",
        "application",
        "gadget",
        "sct",
        "chm",
    ]
)
ARCHIVE = frozenset(
    [
        "zip",
        "rar",
        "7z",
        "gz",
        "tgz",
        "tar",
        "bz2",
        "xz",
        "cab",
        "ace",
        "arj",
        "iso",
        "img",
        "vhd",
        "vhdx",
    ]
)
HTML = frozenset(["htm", "html", "shtml", "xhtml", "svg", "mht", "mhtml"])
DECOY = frozenset(
    [
        "pdf",
        "doc",
        "docx",
        "xls",
        "xlsx",
        "ppt",
        "pptx",
        "txt",
        "rtf",
        "csv",
        "odt",
        "jpg",
        "jpeg",
        "png",
        "gif",
    ]
)
OFFICE = frozenset(
    [
        "doc",
        "dot",
        "xls",
        "xlt",
        "ppt",
        "pps",
        "docm",
        "dotm",
        "xlsm",
        "xltm",
        "xlam",
        "pptm",
        "potm",
        "ppsm",
        "sldm",
    ]
)

EXECUTABLE_TYPES = (
    "application/vnd.microsoft.portable-executable",
    "application/x-msdownload",
    "application/x-dosexec",
    "application/x-executable",
    "application/x-elf",
    "application/x-mach-binary",
)
GENERIC_TYPES = frozenset(
    {"application/octet-stream", "binary/octet-stream", "application/x-download"}
)

# Invisible characters that change the direction text is displayed in.
BIDI_CONTROLS = re.compile("[‎‏‪-‮⁦-⁩]")

SMUGGLING_MARKERS = (
    "atob(",
    "new blob(",
    "createobjecturl",
    ".download",
    "mssaveoropenblob",
    "fromcharcode",
    "document.write(unescape",
    "<form",
)


class MacroScanner(Protocol):
    def has_macros(self, filename: str, content: bytes) -> bool: ...


class OleMacroScanner:
    """oletools' VBA parser: reads macro code, never runs it."""

    def has_macros(self, filename: str, content: bytes) -> bool:
        from oletools.olevba import TYPE_TEXT, VBA_Parser

        parser = None
        try:
            parser = VBA_Parser(filename, data=content)
            # When olevba can't read a file as Office, it falls back to treating
            # the bytes as VBA source text, and then "finds" macros in anything.
            # Only results from a real Office container count.
            if parser.type == TYPE_TEXT:
                return False
            return bool(parser.detect_vba_macros())
        except Exception as exc:
            logger.debug("olevba could not read an attachment (%s)", type(exc).__name__)
            return False
        finally:
            if parser is not None:
                parser.close()


def _name(attachment: Attachment) -> str:
    # Windows ignores trailing dots and spaces, so "invoice.exe. " runs as .exe.
    return (attachment.filename or "").strip().rstrip(". ")


def _extensions(name: str) -> list[str]:
    parts = [p.strip().lower() for p in name.split(".")]
    return parts[1:] if len(parts) > 1 else []


def _category(media_type: str | None) -> str | None:
    """A coarse kind of file, so 'zip' and 'docx' (also a zip) agree."""
    if not media_type:
        return None
    t = media_type.lower()
    if t in EXECUTABLE_TYPES:
        return "executable"
    if (
        "macroenabled" in t
        or "openxmlformats" in t
        or t
        in (
            "application/zip",
            "application/x-zip-compressed",
            "application/java-archive",
            "application/vnd.oasis.opendocument.text",
        )
    ):
        return "zip"
    if t == "application/pdf":
        return "pdf"
    if (
        t.startswith(("application/msword", "application/vnd.ms-"))
        or t == "application/x-ole-storage"
    ):
        return "ole"
    if t.startswith("image/") and t != "image/svg+xml":
        return "image"
    if t in ("text/html", "image/svg+xml", "application/xhtml+xml"):
        return "html"
    return None


_EXTENSION_CATEGORY = {
    **dict.fromkeys(EXECUTABLE, "executable"),
    **dict.fromkeys(
        [
            "zip",
            "docx",
            "xlsx",
            "pptx",
            "docm",
            "xlsm",
            "pptm",
            "dotm",
            "xltm",
            "xlam",
            "potm",
            "ppsm",
            "jar",
            "odt",
        ],
        "zip",
    ),
    "pdf": "pdf",
    **dict.fromkeys(["doc", "dot", "xls", "xlt", "ppt", "pps"], "ole"),
    **dict.fromkeys(["png", "jpg", "jpeg", "gif", "bmp", "webp"], "image"),
    **dict.fromkeys(["htm", "html", "xhtml", "svg"], "html"),
}


@dataclass(frozen=True)
class AttachmentCheck:
    macros: MacroScanner = field(default_factory=OleMacroScanner)
    name: str = "email.attachments"

    async def run(self, msg: ParsedEmail, ctx: CheckContext) -> list[Finding]:
        findings: list[Finding] = []
        for attachment in msg.attachments:
            findings.extend(await self._inspect(attachment))
        return findings

    async def _inspect(self, a: Attachment) -> list[Finding]:
        name = _name(a)
        shown = BIDI_CONTROLS.sub("<RLO>", name) or "(unnamed)"
        exts = _extensions(BIDI_CONTROLS.sub("", name))
        last = exts[-1] if exts else ""
        sniffed = _category(a.sniffed_type)
        proof = (BodyEvidence(excerpt=f"attachment: {shown} ({a.declared_type}, {a.size} bytes)"),)
        out: list[Finding] = []

        def add(what: str, severity: Severity, title: str, explanation: str) -> None:
            out.append(
                Finding(
                    id=f"{self.name}.{what}",
                    check=self.name,
                    severity=severity,
                    title=title,
                    explanation=explanation,
                    evidence=proof,
                )
            )

        if BIDI_CONTROLS.search(name):
            add(
                "bidi_name",
                Severity.CRITICAL,
                "The file name hides its real ending",
                f"The file name contains an invisible character that reverses the text after "
                f"it, so the name is displayed differently from what it really is: {shown}. "
                "This has no legitimate use in a file name.",
            )
        if len(exts) >= 2 and last in EXECUTABLE and exts[-2] in DECOY:
            add(
                "double_extension",
                Severity.CRITICAL,
                "A program disguised as a document",
                f"'{shown}' looks like a .{exts[-2]} file, but the real ending is .{last}: it's "
                "a program. Windows often hides the last ending, so you'd see only the fake one.",
            )
        if last in EXECUTABLE or sniffed == "executable":
            add(
                "executable",
                Severity.HIGH,
                "A program or script is attached",
                f"'{shown}' is "
                + (f"a .{last} file, which" if last in EXECUTABLE else "really a program, which")
                + " runs code on your computer as soon as it's opened. Legitimate senders "
                "almost never email programs.",
            )
        if last in ARCHIVE:
            locked = self._password_protected(a.content)
            add(
                "archive",
                Severity.MEDIUM if locked else Severity.LOW,
                "A password-protected archive" if locked else "An archive is attached",
                f"'{shown}' is an archive or disk image, which can carry files past mail "
                "scanners."
                + (
                    " It's password-protected, so scanners can't look inside at all."
                    if locked
                    else " Archives are common in ordinary mail too, so this is only supporting "
                    "evidence."
                ),
            )
        maybe_office = last in OFFICE or "macroenabled" in a.declared_type.lower()
        if maybe_office and await asyncio.to_thread(
            self.macros.has_macros, name or "attachment", a.content
        ):
            add(
                "macros",
                Severity.HIGH,
                "An Office file with macros",
                f"'{shown}' contains VBA macros: code that runs when you click 'Enable "
                "content'. Macro documents are one of the most common ways malware gets in.",
            )
        if last in HTML or _category(a.declared_type) == "html" or sniffed == "html":
            markers = self._smuggling_markers(a.content)
            add(
                "html",
                Severity.HIGH if markers else Severity.MEDIUM,
                "A web page is attached",
                f"'{shown}' is a web page. Opened, it runs in your browser, where it can show a "
                "fake login form or build a file and download it."
                + (f" It contains code that does that: {', '.join(markers)}." if markers else ""),
            )
        mismatch = self._type_mismatch(last, a.declared_type, sniffed)
        if mismatch:
            add(
                "type_mismatch",
                Severity.HIGH if sniffed == "executable" else Severity.MEDIUM,
                "The file isn't what it claims to be",
                f"'{shown}' claims to be {mismatch}, but its contents are "
                f"{'a program' if sniffed == 'executable' else f'a {sniffed} file'}. A file "
                "disguised as something else is trying to get past someone.",
            )
        return out

    @staticmethod
    def _password_protected(content: bytes) -> bool:
        try:
            with zipfile.ZipFile(io.BytesIO(content)) as archive:
                return any(info.flag_bits & 0x1 for info in archive.infolist())
        except (zipfile.BadZipFile, ValueError, OSError):
            return False

    @staticmethod
    def _smuggling_markers(content: bytes) -> list[str]:
        text = content.decode("latin-1").lower()
        return [m for m in SMUGGLING_MARKERS if m in text][:4]

    @staticmethod
    def _type_mismatch(ext: str, declared: str, sniffed: str | None) -> str | None:
        if sniffed is None:
            return None
        by_ext = _EXTENSION_CATEGORY.get(ext)
        if by_ext and by_ext != sniffed:
            return f"a .{ext} file"
        if declared.lower() not in GENERIC_TYPES:
            by_type = _category(declared)
            if by_type and by_type != sniffed:
                return f"type {declared}"
        return None
