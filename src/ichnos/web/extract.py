"""HTML asset, comment, email, and form extractor."""

from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import Any


class HTMLExtractor(HTMLParser):
    """Parses HTML document to extract links, scripts, forms, and comments."""

    def __init__(self):
        super().__init__()
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.images: list[str] = []
        self.comments: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self.current_form: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]):
        attr_dict = {k.lower(): v for k, v in attrs if v is not None}

        if tag == "a" and "href" in attr_dict:
            self.links.append(attr_dict["href"])
        elif tag == "script" and "src" in attr_dict:
            self.scripts.append(attr_dict["src"])
        elif tag == "img" and "src" in attr_dict:
            self.images.append(attr_dict["src"])
        elif tag == "form":
            self.current_form = {
                "action": attr_dict.get("action", ""),
                "method": attr_dict.get("method", "GET").upper(),
                "inputs": [],
            }
        elif tag == "input" and self.current_form is not None:
            self.current_form["inputs"].append(
                {
                    "name": attr_dict.get("name", ""),
                    "type": attr_dict.get("type", "text"),
                    "value": attr_dict.get("value", ""),
                }
            )

    def handle_endtag(self, tag: str):
        if tag == "form" and self.current_form is not None:
            self.forms.append(self.current_form)
            self.current_form = None

    def handle_comment(self, data: str):
        self.comments.append(data.strip())


def extract_assets(html_content: str) -> dict[str, Any]:
    """Extracts links, scripts, images, forms, comments, and emails from HTML string."""
    parser = HTMLExtractor()
    parser.feed(html_content)

    # Regex for emails
    emails = sorted(
        set(re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", html_content))
    )

    # Regex for API endpoints / URLs
    api_endpoints = sorted(set(re.findall(r"['\"](/api/[a-zA-Z0-9_/.-]+)['\"]", html_content)))

    return {
        "links": sorted(set(parser.links)),
        "scripts": sorted(set(parser.scripts)),
        "images": sorted(set(parser.images)),
        "comments": parser.comments,
        "forms": parser.forms,
        "emails": emails,
        "api_endpoints": api_endpoints,
    }
