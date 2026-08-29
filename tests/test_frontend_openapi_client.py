import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from scripts.verify_openapi_client import (
    checked_in_contracts_are_current,
    normalized_contract,
)


ROOT = Path(__file__).resolve().parents[1]


class FrontendOpenApiClientTests(unittest.TestCase):
    def test_generated_contract_comparison_is_newline_independent(self) -> None:
        with TemporaryDirectory() as directory:
            lf = Path(directory) / "lf.ts"
            crlf = Path(directory) / "crlf.ts"
            lf.write_bytes(b"export interface A {}\n")
            crlf.write_bytes(b"export interface A {}\r\n")
            self.assertEqual(normalized_contract(lf), normalized_contract(crlf))

    def test_generated_contract_comparison_rejects_stale_checked_in_schema(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            generated_schema = root / "generated.json"
            checked_in_schema = root / "checked-in.json"
            generated_types = root / "generated.ts"
            checked_in_types = root / "checked-in.ts"
            generated_schema.write_text('{"openapi":"3.1.0"}\n', encoding="utf-8")
            checked_in_schema.write_text('{"openapi":"3.0.0"}\n', encoding="utf-8")
            generated_types.write_text("export interface A {}\n", encoding="utf-8")
            checked_in_types.write_text("export interface A {}\n", encoding="utf-8")

            self.assertFalse(
                checked_in_contracts_are_current(
                    generated_schema=generated_schema,
                    checked_in_schema=checked_in_schema,
                    generated_types=generated_types,
                    checked_in_types=checked_in_types,
                )
            )

    def test_frontend_uses_generated_typed_client(self) -> None:
        package = json.loads((ROOT / "frontend" / "package.json").read_text(encoding="utf-8"))
        api_source = (ROOT / "frontend" / "src" / "api.ts").read_text(encoding="utf-8")
        types_source = (ROOT / "frontend" / "src" / "types.ts").read_text(encoding="utf-8")
        gate_source = (ROOT / "scripts" / "quality_gate.ps1").read_text(encoding="utf-8")
        ci_source = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

        self.assertEqual(package["dependencies"]["openapi-fetch"], "0.17.0")
        self.assertEqual(package["devDependencies"]["openapi-typescript"], "7.13.0")
        self.assertIn("createClient<paths>", api_source)
        self.assertIn("./generated/openapi", api_source)
        self.assertIn("components['schemas']", types_source)
        self.assertNotIn("fetch(`", api_source)
        self.assertNotIn("JSON.stringify", api_source)
        self.assertIn("npm run check:api", gate_source)
        self.assertIn("playwright install --with-deps chromium", ci_source)
        self.assertIn("npm run test:e2e", ci_source)


if __name__ == "__main__":
    unittest.main()
