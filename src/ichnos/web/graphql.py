"""GraphQL introspection, endpoint discovery, and schema analysis.

Supports:
- Standard GraphQL full introspection query generation
- Endpoint candidate path discovery
- Schema analysis (queries, mutations, types, sensitive fields)
- Error-based field suggestion parsing for schema recovery when introspection is disabled
"""

from __future__ import annotations

import json
import re
from typing import Any

# Standard full GraphQL introspection query compatible with GraphQL specs
GRAPHQL_INTROSPECTION_QUERY = """query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
        args {
          name
          description
          type {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
          defaultValue
        }
        type {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
            }
          }
        }
        isDeprecated
        deprecationReason
      }
      inputFields {
        name
        description
        type {
          kind
          name
          ofType {
            kind
            name
          }
        }
        defaultValue
      }
      interfaces {
        kind
        name
      }
      enumValues(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
      }
      possibleTypes {
        kind
        name
      }
    }
  }
}"""

# Quick lightweight probe query to verify if endpoint speaks GraphQL
GRAPHQL_PROBE_QUERY = "query { __typename }"

# Common GraphQL endpoint paths
COMMON_GRAPHQL_PATHS = [
    "/graphql",
    "/graphiql",
    "/api/graphql",
    "/v1/graphql",
    "/v2/graphql",
    "/graphql/console",
    "/v1/explorer",
    "/api",
    "/query",
]

_SENSITIVE_FIELD_PATTERNS = re.compile(
    r"(flag|pass(word)?|secret|token|admin|auth|api[_-]?key|credential|private|hash|seed)",
    re.IGNORECASE,
)


def get_introspection_query() -> str:
    """Returns the standard GraphQL introspection query string."""
    return GRAPHQL_INTROSPECTION_QUERY


def parse_introspection_schema(schema_json: dict[str, Any] | str) -> dict[str, Any]:
    """Parses a GraphQL introspection result and extracts schema details.

    Args:
        schema_json: The dictionary or raw JSON string of the introspection response
                     (containing data.__schema or __schema).

    Returns:
        Structured dictionary with queries, mutations, subscriptions, types, enums,
        and flagged sensitive fields.
    """
    if isinstance(schema_json, str):
        schema_json = json.loads(schema_json)

    schema = schema_json.get("data", {}).get("__schema") or schema_json.get("__schema")
    if not schema:
        raise ValueError("Invalid GraphQL introspection data: missing __schema")

    query_type_name = (schema.get("queryType") or {}).get("name")
    mutation_type_name = (schema.get("mutationType") or {}).get("name")
    subscription_type_name = (schema.get("subscriptionType") or {}).get("name")

    types_list = schema.get("types", [])
    queries: list[dict[str, Any]] = []
    mutations: list[dict[str, Any]] = []
    subscriptions: list[dict[str, Any]] = []
    custom_types: list[dict[str, Any]] = []
    sensitive_fields: list[dict[str, Any]] = []

    for t in types_list:
        name = t.get("name", "")
        if name.startswith("__"):
            continue  # Skip internal introspection meta-types

        kind = t.get("kind", "")
        fields = t.get("fields") or []

        def _format_type(type_dict: dict[str, Any] | None) -> str:
            if not type_dict:
                return "Unknown"
            kind = type_dict.get("kind", "")
            if kind == "NON_NULL":
                return f"{_format_type(type_dict.get('ofType'))}!"
            if kind == "LIST":
                return f"[{_format_type(type_dict.get('ofType'))}]"
            return str(type_dict.get("name") or "Unknown")

        parsed_fields = []
        for f in fields:
            f_name = f.get("name", "")
            f_type = _format_type(f.get("type"))
            args = [
                {"name": a.get("name"), "type": _format_type(a.get("type"))}
                for a in (f.get("args") or [])
            ]
            field_entry = {
                "name": f_name,
                "type": f_type,
                "args": args,
                "description": f.get("description"),
            }
            parsed_fields.append(field_entry)

            if _SENSITIVE_FIELD_PATTERNS.search(f_name):
                sensitive_fields.append(
                    {
                        "parent_type": name,
                        "field": f_name,
                        "type": f_type,
                    }
                )

        if name == query_type_name:
            queries.extend(parsed_fields)
        elif name == mutation_type_name:
            mutations.extend(parsed_fields)
        elif name == subscription_type_name:
            subscriptions.extend(parsed_fields)
        else:
            custom_types.append(
                {
                    "name": name,
                    "kind": kind,
                    "fields": parsed_fields,
                    "description": t.get("description"),
                }
            )

    return {
        "query_type": query_type_name,
        "mutation_type": mutation_type_name,
        "subscription_type": subscription_type_name,
        "queries": queries,
        "mutations": mutations,
        "subscriptions": subscriptions,
        "custom_types": custom_types,
        "sensitive_fields": sensitive_fields,
    }


def parse_field_suggestions(error_message: str) -> list[str]:
    """Extracts field suggestions from GraphQL error messages (Clairvoyance technique).

    E.g.: 'Cannot query field "fla" on type "Query". Did you mean "flag" or "flat"?'
    """
    suggestions: list[str] = []
    # Match patterns like: Did you mean "foo", "bar", or "baz"?
    match = re.search(r'Did you mean\s+([^?]+)\?', error_message, re.IGNORECASE)
    if match:
        body = match.group(1)
        found = re.findall(r'"([^"]+)"', body)
        suggestions.extend(found)
    return suggestions
