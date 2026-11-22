"""Detection rules.

Each rule is a compiled regex plus metadata. Rules run against several views
of the input (original, folded, decoded segments, HTML comments) and every
match becomes a Finding with a human-readable explanation.

Severity is a triage hint, not a proof of malice. Benign text can match;
that is what the hard-negative corpus measures.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Pattern

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}


@dataclass(frozen=True)
class Rule:
    rule_id: str
    category: str
    severity: str
    pattern: Pattern[str]
    explanation: str


@dataclass
class Finding:
    rule_id: str
    category: str
    severity: str
    view: str           # which text view matched: original, folded, decoded, html-comment
    matched: str        # the matched text, truncated
    explanation: str


def _rx(pattern: str) -> Pattern[str]:
    return re.compile(pattern, re.IGNORECASE | re.DOTALL)


RULES: List[Rule] = [
    Rule("PI001", "instruction_override", "high",
         _rx(r"\b(ignore|disregard|forget|override|bypass)\b[^.\n]{0,60}\b(previous|prior|above|earlier|all|your|initial|original)\b[^.\n]{0,60}\b(instruction|instructions|directives|rules|guidelines|prompt|prompts|constraints)\b"),
         "text tells a model to ignore or replace earlier instructions"),
    Rule("PI002", "instruction_override", "high",
         _rx(r"\b(new|updated|real|actual)\s+(system\s+)?(instructions?|directives?|rules?)\s*[:>]"),
         "text presents replacement instructions as authoritative"),
    Rule("PI003", "role_reassignment", "high",
         _rx(r"\b(from\s+now\s+on\s+you\s+(are|will)|pretend\s+to\s+be|roleplay\s+as|assume\s+the\s+role)\b[^.\n]{0,80}|\byou\s+are\s+now\s+(an?|the)\s+[^.\n]{0,40}\b(assistant|model|ai|bot|version)\b|\bact\s+as\s+(?!if\b)[^.\n]{0,60}\b(assistant|model|ai|bot|admin|administrator|expert|human|persona|character)\b"),
         "text tries to reassign the model's role or persona"),
    Rule("PI004", "role_reassignment", "high",
         _rx(r"\b(DAN\b|do\s+anything\s+now|jailbreak|god\s+mode|no\s+(restrictions?|guidelines?|filters?|limits?)|without\s+(any\s+)?(filters?|restrictions?|limits?|guidelines?))"),
         "text references known jailbreak personas or unrestricted modes"),
    Rule("PI005", "system_prompt_exfil", "high",
         _rx(r"\b(repeat|reveal|print|show|display|output|leak|tell\s+me)\b[^.\n]{0,50}\b(system\s+prompt|your\s+instructions|initial\s+(prompt|instructions)|hidden\s+(prompt|instructions)|configuration|your\s+rules)\b"),
         "text asks the model to reveal its system prompt or configuration"),
    Rule("PI006", "delimiter_smuggling", "high",
         _rx(r"(<\|im_start\|>|<\|im_end\|>|<\|system\|>|\[INST\]|\[/INST\]|<<SYS>>|<<\/SYS>>|<\|endoftext\|>)"),
         "text contains model-control tokens that imitate chat markup"),
    Rule("PI007", "delimiter_smuggling", "medium",
         _rx(r"```\s*(system|prompt|instructions?)\b"),
         "fenced code block labelled as system or instructions"),
    Rule("PI008", "indirect_injection", "medium",
         _rx(r"\b(dear|hello|hi|attention|note\s+to)\s+(ai|assistant|model|chatbot|gpt|llm|claude|gemini|copilot)\b"),
         "text addresses an AI assistant directly inside data content"),
    Rule("PI009", "indirect_injection", "medium",
         _rx(r"\b(when\s+you\s+(read|process|summari[sz]e|see)\s+this|if\s+you\s+are\s+an?\s+(ai|assistant|llm|language\s+model)\s+(read|process|summari[sz]e|scan|pars|analy[sz]))"),
         "text conditions behaviour on being processed by a model"),
    Rule("PI010", "exfil_channel", "high",
         _rx(r"!\[[^\]]*\]\(\s*https?://[^)\s]+\?[^)\s]+\)"),
         "markdown image with a query string, a known data-exfiltration channel"),
    Rule("PI011", "exfil_channel", "high",
         _rx(r"\b(send|post|upload|transmit|forward|exfiltrate)\b[^.\n]{0,60}\b(to|via)\b[^.\n]{0,40}\bhttps?://"),
         "text instructs sending data to a URL"),
    Rule("PI012", "exfil_channel", "medium",
         _rx(r"\b(append|attach|include|encode)\b[^.\n]{0,50}\b(to|into|in)\b[^.\n]{0,30}\b(url|link|request|query)\b"),
         "text instructs embedding data into an outbound link or request"),
    Rule("PI013", "hidden_text", "medium",
         _rx(r"(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0|color\s*:\s*(white|transparent|#fff))"),
         "text contains CSS that hides content from human readers"),
    Rule("PI014", "persistence", "medium",
         _rx(r"\bin\s+all\s+(future|subsequent)\s+(responses?|replies|conversations?|sessions?)\b|\b(remember|save|store|keep)\b[^.\n]{0,60}\b(for\s+all\s+future|to\s+(memory|notes|context)|in\s+(memory|your\s+notes))\b"),
         "text tries to persist an instruction across turns or sessions"),
    Rule("PI015", "safety_bypass", "high",
         _rx(r"\b(ignore|disable|turn\s+off|remove|skip|bypass)\b[^.\n]{0,40}\b(safety\s+(filters?|mechanisms?|systems?|guidelines?|warnings?)|safeguards?|guardrails?|moderation|content\s+polic(y|ies)|ethics\s+(rules?|guidelines?))\b"),
         "text asks to disable safety mechanisms"),
    Rule("PI016", "instruction_override", "medium",
         _rx(r"\b(do\s+not|don't|never)\b[^.\n]{0,40}\b(tell|inform|reveal\s+to|show)\b[^.\n]{0,30}\b(the\s+user|the\s+human|the\s+owner)\b|\b(never|do\s+not|don't)\s+(show|share|reveal|mention)\s+[^.\n]{0,25}\b(these|this|my|your)\s+(instructions?|prompt|rules?|directives?)\b"),
         "text instructs concealing actions from the user"),
]
