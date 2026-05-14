import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from engine.api.base import DLPTarget
from engine.pipeline.base import Finding, Severity


def _write_control(overrides: dict | None = None) -> None:
    ctrl = {
        "regex_enabled": False,
        "asset_enabled": False,
        "confidence_threshold": 0.5,
    }
    if overrides:
        ctrl.update(overrides)
    Path("/tmp/dlp-control.json").write_text(json.dumps(ctrl), encoding="utf-8")


class FakeSLMStage:
    def __init__(self) -> None:
        self.calls: list[list[DLPTarget]] = []

    def scan(self, targets: list[DLPTarget], prior_findings: list[Finding]) -> list[Finding]:
        del prior_findings
        self.calls.append(list(targets))
        findings: list[Finding] = []
        for target in targets:
            if "Alice" not in target.text:
                continue
            local_start = target.text.index("Alice")
            start = target.base_offset + local_start
            findings.append(Finding(
                stage="slm",
                rule="person_name",
                severity=Severity.HIGH,
                field_path=target.field_path,
                role=target.role,
                match_text="Alice",
                match_start=start,
                match_end=start + len("Alice"),
                context_before=target.text[:local_start],
                context_after=target.text[local_start + len("Alice"):],
                confidence=0.9,
                history=target.history,
            ))
        return findings


class PipelineSLMInputTests(unittest.TestCase):
    def _preserve_control(self) -> tuple[Path, str | None]:
        control_path = Path("/tmp/dlp-control.json")
        previous_control = control_path.read_text(encoding="utf-8") if control_path.exists() else None
        return control_path, previous_control

    def _restore_control(self, control_path: Path, previous_control: str | None) -> None:
        if previous_control is None:
            control_path.unlink(missing_ok=True)
        else:
            control_path.write_text(previous_control, encoding="utf-8")

    def test_slm_inputs_skip_static_roles_and_reuse_cache(self) -> None:
        import engine.pipeline as pipeline

        control_path, previous_control = self._preserve_control()

        try:
            _write_control()
            pipeline._msg_cache.clear()
            pipeline._slm_cache.clear()
            pipeline._cache_stats.update({"hits": 0, "misses": 0})
            pipeline._slm_cache_stats.update({"hits": 0, "misses": 0})

            fake_slm = FakeSLMStage()
            targets = [
                DLPTarget("messages[0].content", "user", "Alice lives in Seoul", history=True),
                DLPTarget("messages[2].content", "user", "Alice moved to Busan"),
                DLPTarget("tools[0].function.description", "tool_def", "tool schema mentions Alice"),
                DLPTarget("system", "system", "system prompt mentions Alice"),
                DLPTarget("messages[1].content", "assistant", "assistant mentions Alice"),
            ]

            with patch.object(pipeline, "_slm_stage", fake_slm):
                first = pipeline.run_pipeline(targets, slm_enabled=True)
                self.assertEqual(len(fake_slm.calls), 1)
                self.assertEqual(
                    [target.field_path for target in fake_slm.calls[0]],
                    ["messages[0].content", "messages[2].content"],
                )
                self.assertEqual(
                    {finding.field_path for finding in first.findings},
                    {"messages[0].content", "messages[2].content"},
                )

                second = pipeline.run_pipeline(targets, slm_enabled=True)
                self.assertEqual(len(fake_slm.calls), 1)
                self.assertEqual(
                    {finding.field_path for finding in second.findings},
                    {"messages[0].content", "messages[2].content"},
                )
                self.assertEqual(pipeline.get_cache_stats()["slm_hits"], 2)
        finally:
            self._restore_control(control_path, previous_control)

    def test_slm_uses_unresolved_windows_and_restores_original_offsets(self) -> None:
        import engine.pipeline as pipeline

        control_path, previous_control = self._preserve_control()

        try:
            _write_control({"regex_enabled": True, "asset_enabled": False, "confidence_threshold": 0.5})
            pipeline._msg_cache.clear()
            pipeline._slm_cache.clear()
            pipeline._cache_stats.update({"hits": 0, "misses": 0})
            pipeline._slm_cache_stats.update({"hits": 0, "misses": 0})

            fake_slm = FakeSLMStage()
            text = "전화번호 010-1234-5678 처리 후 Alice lives in Seoul and works at Corp headquarters."
            alice_index = text.index("Alice")
            targets = [DLPTarget("messages[0].content", "user", text)]

            with patch.object(pipeline, "_slm_stage", fake_slm):
                result = pipeline.run_pipeline(targets, slm_enabled=True)

            self.assertEqual(len(fake_slm.calls), 1)
            call_targets = fake_slm.calls[0]
            self.assertTrue(call_targets)
            self.assertTrue(all("010-1234-5678" not in target.text for target in call_targets))

            alice_target = next(target for target in call_targets if "Alice" in target.text)
            self.assertEqual(
                alice_target.base_offset,
                alice_index - alice_target.text.index("Alice"),
            )

            alice_finding = next(finding for finding in result.findings if finding.rule == "person_name")
            self.assertEqual(alice_finding.match_start, alice_index)
            self.assertEqual(alice_finding.match_end, alice_index + len("Alice"))
        finally:
            self._restore_control(control_path, previous_control)


if __name__ == "__main__":
    unittest.main()
