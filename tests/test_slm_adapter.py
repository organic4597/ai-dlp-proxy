import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from engine.api.base import DLPTarget
from engine.pipeline.base import Finding, Severity
from engine.pipeline.slm_adapter import Detection, SLMAdapter, filter_by_prior, parse_model_output
from engine.pipeline.slm_stage import SLMStage


class DummyAdapter(SLMAdapter):
    def __init__(self) -> None:
        self.stats = {"calls": 0, "chunks": 0, "infer_ms": 0.0, "errors": 0}

    def detect(self, text: str, prior_ranges=None) -> list[dict]:
        detections: list[Detection] = []
        for rule, needle in (("person_name", "Alice"), ("address", "Seoul")):
            start = text.find(needle)
            if start >= 0:
                detections.append(Detection(rule, start, start + len(needle), needle, 0.9))
        if prior_ranges:
            detections = filter_by_prior(detections, prior_ranges)
        return [detection.to_dict() for detection in detections]


class FakeRuntimeAdapter:
    def __init__(self) -> None:
        self.calls: list[tuple[list[str], list[list[tuple[int, int]]]]] = []

    def detect_combined(self, texts: list[str], prior_ranges_per_text: list[list[tuple[int, int]]]) -> list[list[dict]]:
        self.calls.append((texts, prior_ranges_per_text))
        results: list[list[dict]] = []
        for text in texts:
            local_results: list[dict] = []
            if "Alice" in text:
                start = text.index("Alice")
                local_results.append({
                    "rule": "person_name",
                    "start": start,
                    "end": start + len("Alice"),
                    "text": "Alice",
                    "confidence": 0.9,
                })
            results.append(local_results)
        return results

    def get_stats(self) -> dict:
        return {"chunks": 1, "infer_ms": 10.0, "errors": 0}


class SLMAdapterTests(unittest.TestCase):
    def test_parse_model_output_normalizes_rules(self) -> None:
        raw = 'noise [["api_key", "sk-test"], ["private_key", "pem"], ["card_number", "4111"], ["aws_key", "AKIA"], ["email", "<<<email>>>"]] tail'
        self.assertEqual(
            parse_model_output(raw),
            [
                ("api_key_assignment", "sk-test"),
                ("pem_private_key", "pem"),
                ("credit_card", "4111"),
                ("aws_access_key", "AKIA"),
            ],
        )

    def test_filter_by_prior_uses_half_overlap_rule(self) -> None:
        detections = [
            Detection("person_name", 10, 15, "Alice", 0.9),
            Detection("address", 20, 30, "Seoul", 0.9),
        ]
        kept = filter_by_prior(detections, [(10, 15), (25, 27)])
        self.assertEqual([detection.rule for detection in kept], ["address"])

    def test_detect_combined_splits_back_to_local_offsets(self) -> None:
        adapter = DummyAdapter()
        results = adapter.detect_combined(["prefix", "Alice in Seoul"], [[], []])
        self.assertEqual(results[0], [])
        self.assertEqual(results[1][0]["rule"], "person_name")
        self.assertEqual(results[1][0]["start"], 0)
        self.assertEqual(results[1][1]["rule"], "address")
        self.assertEqual(results[1][1]["start"], 9)


class SLMStageAdapterTests(unittest.TestCase):
    def test_stage_adapter_branch_restores_base_offset(self) -> None:
        stage = SLMStage(backend="gguf")
        stage._adapter = FakeRuntimeAdapter()
        stage._active_backend = "adapter"
        stage._ensure_loaded = lambda: True  # type: ignore[method-assign]

        target = DLPTarget(
            field_path="messages[0].content",
            role="user",
            text="prefix Alice suffix",
            base_offset=20,
        )
        prior = [
            Finding(
                stage="regex",
                rule="dummy",
                severity=Severity.HIGH,
                field_path="messages[0].content",
                role="user",
                match_text="prefix",
                match_start=20,
                match_end=26,
                context_before="",
                context_after="",
                confidence=1.0,
            )
        ]

        findings = stage.scan([target], prior)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].match_start, 27)
        self.assertEqual(findings[0].match_end, 32)
        texts, prior_ranges = stage._adapter.calls[0]
        self.assertEqual(texts, ["prefix Alice suffix"])
        self.assertEqual(prior_ranges, [[(0, 6)]])


if __name__ == "__main__":
    unittest.main()