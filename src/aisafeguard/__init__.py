"""AISafe Guard — Safety rails for every AI app.

Model-agnostic guardrails for LLM applications.

Usage:
    from aisafeguard import Guard, guard

    # Decorator pattern
    @guard(input=["prompt_injection", "pii"], output=["toxicity"])
    async def ask(prompt: str) -> str:
        return await llm.generate(prompt)

    # Context manager pattern
    async with Guard(config="aisafe.yaml") as g:
        result = await g.scan_input(prompt)
"""

from aisafeguard.decorator import guard
from aisafeguard.guard import Guard
from aisafeguard.models import (
    Action,
    Finding,
    PipelineResult,
    Report,
    ScanResult,
    Tier,
)
from aisafeguard.policy import PolicyViolation

# Register built-in scanners
from aisafeguard.guard import register_input_scanner, register_output_scanner
from aisafeguard.scanners.prompt_injection import PromptInjectionScanner
from aisafeguard.scanners.jailbreak import JailbreakScanner
from aisafeguard.scanners.pii import PIIInputScanner, PIIOutputScanner
from aisafeguard.scanners.toxicity import ToxicityScanner
from aisafeguard.scanners.malicious_url import MaliciousURLScanner
from aisafeguard.scanners.topic_ban import TopicBanScanner
from aisafeguard.scanners.relevance import RelevanceScanner

# Input scanners
register_input_scanner("prompt_injection", PromptInjectionScanner)
register_input_scanner("jailbreak", JailbreakScanner)
register_input_scanner("pii", PIIInputScanner)
register_input_scanner("topic_ban", TopicBanScanner)

# Output scanners
register_output_scanner("toxicity", ToxicityScanner)
register_output_scanner("pii", PIIOutputScanner)
register_output_scanner("malicious_url", MaliciousURLScanner)
register_output_scanner("relevance", RelevanceScanner)

__version__ = "0.1.1"

__all__ = [
    "Guard",
    "guard",
    "Action",
    "Finding",
    "PipelineResult",
    "PolicyViolation",
    "Report",
    "ScanResult",
    "Tier",
    "__version__",
]
