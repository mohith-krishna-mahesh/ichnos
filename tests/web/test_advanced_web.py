"""Tests for advanced web reconnaissance and exploitation modules.

Covers:
- GraphQL introspection query generation, schema parsing, and suggestion analysis
- SSTI fingerprinting, decision tree evaluation, and exploit payload generation
"""


from ichnos.web.graphql import (
    get_introspection_query,
    parse_field_suggestions,
    parse_introspection_schema,
)
from ichnos.web.ssti import (
    fingerprint_ssti,
    generate_payload,
    get_detection_probes,
    identify_engine_from_error,
)


def test_graphql_introspection_query():
    q = get_introspection_query()
    assert "__schema" in q
    assert "queryType" in q
    assert "mutationType" in q


def test_graphql_schema_parsing():
    mock_schema = {
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "mutationType": {"name": "Mutation"},
                "subscriptionType": None,
                "types": [
                    {
                        "name": "Query",
                        "kind": "OBJECT",
                        "fields": [
                            {"name": "getFlag", "type": {"name": "String"}},
                            {"name": "userSecretToken", "type": {"name": "String"}},
                        ],
                    },
                    {
                        "name": "User",
                        "kind": "OBJECT",
                        "fields": [
                            {"name": "id", "type": {"name": "ID"}},
                            {"name": "passwordHash", "type": {"name": "String"}},
                        ],
                    },
                ],
            }
        }
    }

    parsed = parse_introspection_schema(mock_schema)
    assert parsed["query_type"] == "Query"
    assert parsed["mutation_type"] == "Mutation"
    assert len(parsed["queries"]) == 2
    # Check sensitive fields flagged
    flagged_fields = [f["field"] for f in parsed["sensitive_fields"]]
    assert "getFlag" in flagged_fields
    assert "userSecretToken" in flagged_fields
    assert "passwordHash" in flagged_fields


def test_graphql_suggestions():
    err = 'Cannot query field "fla" on type "Query". Did you mean "flag" or "flash"?'
    sugg = parse_field_suggestions(err)
    assert "flag" in sugg
    assert "flash" in sugg


def test_ssti_probes_and_fingerprint():
    probes = get_detection_probes()
    assert len(probes) >= 5

    # Test Jinja2 detection: {{7*7}} -> 49 and {{7*'7'}} -> 7777777
    res_jinja = {
        "{{7*7}}": "49",
        "{{7*'7'}}": "7777777",
    }
    fp_j = fingerprint_ssti(res_jinja)
    assert fp_j["engine"] == "Jinja2"
    assert fp_j["confidence"] > 0.9

    # Test Twig detection: {{7*'7'}} -> 49
    res_twig = {
        "{{7*7}}": "49",
        "{{7*'7'}}": "49",
    }
    fp_t = fingerprint_ssti(res_twig)
    assert fp_t["engine"] == "Twig"

    # Test error identification
    err_text = "Traceback: jinja2.exceptions.TemplateSyntaxError: unexpected char"
    eng = identify_engine_from_error(err_text)
    assert "Jinja2" in eng


def test_ssti_payload_generator():
    payloads = generate_payload("jinja2", command="cat flag.txt")
    assert len(payloads) >= 1
    assert any("cat flag.txt" in p["payload"] for p in payloads)

    twig_payloads = generate_payload("twig", command="id")
    assert len(twig_payloads) >= 1
    assert any("id" in p["payload"] for p in twig_payloads)
