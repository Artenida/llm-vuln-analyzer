"""
LLM client.
Sends a prompt to the configured LLM and parses the JSON response
into a VulnerabilityReport.
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import asdict, dataclass
from typing import Optional

import openai

from src.config import LLMConfig
from src.models import CodeSample

logger = logging.getLogger(__name__)


@dataclass
class VulnerabilityReport:
    function_name: Optional[str]
    file_path: Optional[str]
    language: str

    vulnerability_found: bool
    cwe_id: Optional[str]
    affected_lines: list[int]
    severity: Optional[str]           # low / medium / high / critical
    explanation: str
    patch_suggestion: str
    confidence: float
    hallucination_flag: bool

    # set by pipeline, not LLM
    analysis_mode: str = "single_function"
    error: Optional[str] = None


_SAFE_REPORT = VulnerabilityReport(
    function_name=None, file_path=None, language="unknown",
    vulnerability_found=False, cwe_id=None, affected_lines=[],
    severity=None, explanation="Parse error — could not read LLM response.",
    patch_suggestion="", confidence=0.0, hallucination_flag=True,
    error="json_parse_error",
)

SYSTEM_PROMPT = (
    "You are a security-focused code reviewer. "
    "Respond ONLY with a valid JSON object. "
    "Do not include markdown, prose, or text outside the JSON."
)

USER_PROMPT_TEMPLATE = """\
Analyse the following {language} code for security vulnerabilities.

{context_sections}

Respond with this exact JSON schema:
{{
  "vulnerability_found": boolean,
  "cwe_id": string or null,
  "affected_lines": [list of integers],
  "severity": "low" | "medium" | "high" | "critical" | null,
  "explanation": string,
  "patch_suggestion": string,
  "confidence": float between 0.0 and 1.0,
  "hallucination_flag": boolean
}}
"""


class LLMClient:
    def __init__(self, config: LLMConfig):
        self.config = config
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise EnvironmentError(
                "OPENAI_API_KEY environment variable is not set."
            )
        self.client = openai.OpenAI(api_key=api_key)

    def analyze(self, sample: CodeSample,
                context_prompt: Optional[str] = None) -> VulnerabilityReport:
        """
        Analyzes a CodeSample.
        If context_prompt is provided (Phase 2+), it is used as the full
        user message. Otherwise a minimal single-function prompt is built.
        """
        if context_prompt is not None:
            user_message = context_prompt
        else:
            user_message = self._build_single_prompt(sample)

        try:
            response = self.client.chat.completions.create(
                model=self.config.model,
                max_tokens=self.config.max_tokens,
                temperature=self.config.temperature,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user",   "content": user_message},
                ],
            )
            raw = response.choices[0].message.content or ""
            return self._parse_response(raw, sample)

        except openai.OpenAIError as e:
            logger.error("OpenAI API error: %s", e)
            report = _SAFE_REPORT
            report.function_name = sample.function_name
            report.file_path = sample.file_path
            report.language = sample.language.value
            report.error = f"api_error: {e}"
            return report

    # ── prompt builders ───────────────────────────────────────────────────────

    def _build_single_prompt(self, sample: CodeSample) -> str:
        code_section = f"## Function to analyse\n```\n{sample.code}\n```"
        return USER_PROMPT_TEMPLATE.format(
            language=sample.language.value,
            context_sections=code_section,
        )

    # ── response parser ───────────────────────────────────────────────────────

    def _parse_response(self, raw: str, sample: CodeSample) -> VulnerabilityReport:
        # strip markdown code fences if present
        text = raw.strip()
        if text.startswith("```"):
            lines = text.splitlines()
            text = "\n".join(
                line for line in lines
                if not line.startswith("```")
            ).strip()

        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            logger.warning("JSON parse error: %s | raw: %.200s", e, raw)
            report = _SAFE_REPORT
            report.function_name = sample.function_name
            report.file_path = sample.file_path
            report.language = sample.language.value
            return report

        return VulnerabilityReport(
            function_name=sample.function_name,
            file_path=sample.file_path,
            language=sample.language.value,
            vulnerability_found=bool(data.get("vulnerability_found", False)),
            cwe_id=data.get("cwe_id"),
            affected_lines=data.get("affected_lines", []),
            severity=data.get("severity"),
            explanation=data.get("explanation", ""),
            patch_suggestion=data.get("patch_suggestion", ""),
            confidence=float(data.get("confidence", 0.0)),
            hallucination_flag=bool(data.get("hallucination_flag", False)),
        )