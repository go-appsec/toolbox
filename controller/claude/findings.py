"""Finding file writer with slugification and sequencing."""

import os
import re


def slugify(text: str) -> str:
    """Convert text to a URL-safe slug."""
    text = text.lower().strip()
    text = re.sub(r"[^\w\s-]", "", text)
    text = re.sub(r"[-\s]+", "-", text)
    return text.strip("-")


def extract_title(finding_text: str) -> str:
    """Extract the title from a structured finding report."""
    for line in finding_text.splitlines():
        line = line.strip()
        # "Title: ..." or "**Title**: ..." or "**Title:** ..."
        lower = line.lower()
        if lower.startswith("title:"):
            return line.split(":", 1)[1].strip().strip("*")
        if lower.startswith("**title**:") or lower.startswith("**title:**"):
            return line.split(":", 1)[1].strip().strip("*").strip()
        if line.startswith("#") and not line.startswith("####"):
            return line.lstrip("#").strip()
    # Fallback: first non-empty, non-heading line
    for line in finding_text.splitlines():
        line = line.strip()
        if line and not line.startswith("#") and not line.startswith("---"):
            return line[:60]
    return "untitled"


class FindingWriter:
    """Manages writing finding reports to sequenced markdown files."""

    def __init__(self, findings_dir: str):
        self.findings_dir = findings_dir
        self.count = 0
        self.paths: list[str] = []

    def write(self, finding_text: str) -> str:
        """Write a finding to a markdown file. Returns the file path."""
        os.makedirs(self.findings_dir, exist_ok=True)
        self.count += 1

        title = extract_title(finding_text)
        slug = slugify(title)
        if not slug:
            slug = "untitled"
        if len(slug) > 60:
            slug = slug[:60].rstrip("-")

        filename = f"finding-{self.count:02d}-{slug}.md"
        filepath = os.path.join(self.findings_dir, filename)

        with open(filepath, "w") as f:
            f.write(finding_text)
            if not finding_text.endswith("\n"):
                f.write("\n")

        self.paths.append(filepath)
        return filepath
