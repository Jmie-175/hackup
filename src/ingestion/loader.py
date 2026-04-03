
"""
Ingestion loader -- LangChain DocumentLoaders for .md / .json / .txt files.
"""
import json
from pathlib import Path
from langchain_core.documents import Document


def load_markdown(path: Path) -> list[Document]:
    """Split markdown on H2/H3 headings, return LangChain Documents."""
    text = path.read_text(encoding="utf-8")
    sections: list[Document] = []
    current_heading = "Introduction"
    current_lines: list[str] = []

    for line in text.splitlines():
        if line.startswith("## ") or line.startswith("### "):
            if current_lines:
                sections.append(Document(
                    page_content=f"{current_heading}\n\n" + "\n".join(current_lines).strip(),
                    metadata={"source": path.name, "section": current_heading, "type": "research"},
                ))
            current_heading = line.lstrip("#").strip()
            current_lines = []
        else:
            current_lines.append(line)

    if current_lines:
        sections.append(Document(
            page_content=f"{current_heading}\n\n" + "\n".join(current_lines).strip(),
            metadata={"source": path.name, "section": current_heading, "type": "research"},
        ))
    return sections


def load_json_cases(path: Path) -> list[Document]:
    """Load test-case JSON as LangChain Documents."""
    cases = json.loads(path.read_text(encoding="utf-8"))
    return [
        Document(
            page_content=f"[{c['label']}] {c['description']}: {c['input']}",
            metadata={
                "source": path.name,
                "section": c.get("id", "?"),
                "type": "example",
                "label": c.get("label", "UNKNOWN"),
            },
        )
        for c in cases
    ]


def load_all(raw_dir: str = "./data/raw") -> list[Document]:
    """Load all supported files from raw_dir. Returns LangChain Documents."""
    raw_path = Path(raw_dir)
    docs: list[Document] = []

    for file in raw_path.rglob("*"):
        if file.suffix == ".md":
            print(f"  [LOAD] markdown: {file.name}")
            docs.extend(load_markdown(file))
        elif file.suffix == ".json":
            print(f"  [LOAD] json: {file.name}")
            docs.extend(load_json_cases(file))
        elif file.suffix == ".txt":
            print(f"  [LOAD] text: {file.name}")
            docs.append(Document(
                page_content=file.read_text(encoding="utf-8"),
                metadata={"source": file.name, "section": "full_text", "type": "text"},
            ))

    print(f"  [LOAD] Total documents loaded: {len(docs)}")
    return docs
