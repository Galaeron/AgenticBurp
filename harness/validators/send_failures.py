"""Per-validation send accounting: unanswered probes cannot establish a negative."""
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

from harness.safety_gate import SafetyGateBlocked
from .base import ValidationResult


@dataclass
class SendFailures:
    attempted: int = 0
    failures: list[str] = field(default_factory=list)
    refused: int = 0

    @staticmethod
    def label(method, url):
        # Query strings may carry tokens, especially email confirmation links.
        p = urlsplit(url)
        return f"{method} {urlunsplit((p.scheme, p.netloc.rsplit('@', 1)[-1], p.path, '', ''))}"

    def exception(self, label, error):
        blocked = isinstance(error, SafetyGateBlocked)
        self.refused += int(blocked)
        reason = f"refused ({error.decision.reason})" if blocked else type(error).__name__
        self.failures.append(f"{label}: {reason}")

    def outcome(self, label, result):
        if result.ok:
            return
        blocked = not result.executed
        self.refused += int(blocked)
        artifact = getattr(result, 'artifact', None)
        reason = getattr(artifact, 'transport_outcome', '') or result.outcome
        self.failures.append(f"{label}: {'refused ' if blocked else ''}{reason}")

    def result(self, validator, finding_class, check):
        return ValidationResult(
            validator, 'blocked' if self.refused == len(self.failures) == self.attempted
            else 'inconclusive', finding_class, confidence=0.0, confirmed=False,
            summary=f"{check} incomplete: {len(self.failures)} of {self.attempted} send(s) "
                    f"got no response ({'; '.join(self.failures[:4])}); not a negative result",
            evidence='; '.join(self.failures))
