"""Agent-side behavioral signal extraction (Behavioral Detection, Stage 1).

Pure functions only. Inspects raw ``tool_input`` in-process and emits signal
IDs — never raw content. See ``catalog.py`` for the signal definitions and
``extractor.py`` for the entry point.
"""
from __future__ import annotations
