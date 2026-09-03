from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from scripts.summarize_sub2_har import (
    Sub2HarSummaryError,
    summarize_file,
    summarize_har,
)


ORIGIN = "https://ai1.aisb.shop"


def _entry(
    path: str,
    *,
    method: str = "POST",
    request_body: object | None = None,
    response_body: object | None = None,
    query: list[dict[str, str]] | None = None,
    encoded: bool = False,
) -> dict[str, object]:
    request: dict[str, object] = {
        "method": method,
        "url": f"{ORIGIN}{path}",
        "headers": [
            {"name": "Authorization", "value": "Bearer TOP_SECRET_TOKEN"},
            {"name": "Cookie", "value": "session=TOP_SECRET_COOKIE"},
            {"name": "X-Leaky-TOP_SECRET_HEADER", "value": "ignored"},
        ],
        "queryString": query or [],
    }
    if request_body is not None:
        request["postData"] = {"text": json.dumps(request_body)}
    response_content: dict[str, object] = {
        "text": json.dumps(response_body) if response_body is not None else ""
    }
    if encoded:
        response_content["encoding"] = "base64"
    return {
        "request": request,
        "response": {
            "status": 200,
            "headers": [
                {"name": "Content-Type", "value": "application/json"},
                {"name": "X-Leaky-Response", "value": "TOP_SECRET_RESPONSE"},
            ],
            "content": response_content,
        },
        "serverIPAddress": "192.0.2.10",
        "comment": "TOP_SECRET_COMMENT",
    }


def _har(entries: list[dict[str, object]]) -> bytes:
    return json.dumps({"log": {"entries": entries}}).encode("utf-8")


class SummarizeSub2HarTests(unittest.TestCase):
    def test_emits_only_shapes_and_templates_dynamic_values(self) -> None:
        entry = _entry(
            "/api/v1/admin/accounts/900/duplicate?email=person%40example.com",
            request_body={
                "account_ids": [900, 899],
                "credentials": {"access_token": "TOP_SECRET_BODY"},
                "eyJTOP_SECRET_DYNAMIC_KEY": "TOP_SECRET_DYNAMIC_VALUE",
            },
            response_body={
                "data": [{"account_id": 900, "email": "person@example.com"}],
                "refresh_token": "TOP_SECRET_REFRESH",
            },
            query=[
                {"name": "page", "value": "TOP_SECRET_QUERY"},
                {"name": "person@example.com", "value": "TOP_SECRET_QUERY_2"},
            ],
        )

        result = summarize_har(_har([entry]), expected_origin=ORIGIN)
        encoded = json.dumps(result, sort_keys=True)

        self.assertEqual(result["entry_count"], 1)
        shape = result["entries"][0]
        self.assertEqual(
            shape["path"], "/api/v1/admin/accounts/{account_id}/duplicate"
        )
        self.assertEqual(shape["query_fields"], ["page"])
        self.assertEqual(
            shape["request_header_names"], ["authorization", "cookie"]
        )
        self.assertIn("credentials.access_token", shape["request_fields"])
        self.assertIn("data[].email", shape["response_fields"])
        self.assertNotIn("eyJTOP_SECRET_DYNAMIC_KEY", encoded)
        for sentinel in (
            "TOP_SECRET_TOKEN",
            "TOP_SECRET_COOKIE",
            "TOP_SECRET_HEADER",
            "TOP_SECRET_BODY",
            "TOP_SECRET_DYNAMIC_VALUE",
            "TOP_SECRET_QUERY",
            "TOP_SECRET_RESPONSE",
            "TOP_SECRET_COMMENT",
            "person@example.com",
            "192.0.2.10",
        ):
            self.assertNotIn(sentinel, encoded)
        self.assertFalse(result["production_acceptance"])

    def test_filters_other_origins_and_marks_encoded_response_uninspected(self) -> None:
        other = _entry("/api/v1/admin/accounts")
        other["request"]["url"] = "https://example.com/api/v1/admin/accounts"
        encoded = _entry(
            "/api/v1/admin/openai/exchange-code",
            response_body={"access_token": "TOP_SECRET_ENCODED"},
            encoded=True,
        )

        result = summarize_har(_har([other, encoded]), expected_origin=ORIGIN)

        self.assertEqual(result["entry_count"], 1)
        self.assertEqual(
            result["entries"][0]["response_body_kind"], "encoded_uninspected"
        )
        self.assertEqual(result["entries"][0]["response_fields"], [])

    def test_rejects_unknown_methods_duplicate_keys_and_empty_scope(self) -> None:
        with self.assertRaises(Sub2HarSummaryError):
            summarize_har(
                _har([_entry("/api/v1/admin/accounts", method="TRACE")]),
                expected_origin=ORIGIN,
            )
        with self.assertRaises(Sub2HarSummaryError):
            summarize_har(
                b'{"log":{"entries":[],"entries":[]}}',
                expected_origin=ORIGIN,
            )
        with self.assertRaises(Sub2HarSummaryError):
            summarize_har(
                _har([_entry("/public/health")]),
                expected_origin=ORIGIN,
            )

    def test_writes_one_external_summary_without_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "capture.har"
            output = root / "summary.json"
            source.write_bytes(
                _har(
                    [
                        _entry(
                            "/api/v1/admin/accounts/today-stats/batch",
                            request_body={"account_ids": [900]},
                        )
                    ]
                )
            )

            count = summarize_file(source, output, expected_origin=ORIGIN)

            self.assertEqual(count, 1)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["entries"][0]["request_fields"], ["account_ids"])
            with self.assertRaises(Sub2HarSummaryError):
                summarize_file(source, output, expected_origin=ORIGIN)


if __name__ == "__main__":
    unittest.main()
