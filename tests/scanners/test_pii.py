from __future__ import annotations

from aisafeguard.scanners.pii import PIIInputScanner, PIIOutputScanner


async def test_pii_input_detects_and_redacts() -> None:
    scanner = PIIInputScanner()
    result = await scanner.execute("Email me at john@test.com and SSN 123-45-6789")
    assert not result.passed
    assert len(result.findings) == 2
    assert result.sanitized is not None
    assert "john@test.com" not in result.sanitized
    assert "123-45-6789" not in result.sanitized


async def test_pii_output_passes_clean_text() -> None:
    scanner = PIIOutputScanner()
    result = await scanner.execute("The capital of France is Paris.")
    assert result.passed
    assert result.findings == []
    assert result.sanitized is None
