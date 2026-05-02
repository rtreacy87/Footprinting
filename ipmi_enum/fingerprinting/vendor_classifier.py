from __future__ import annotations

from dataclasses import dataclass

from ..context import ScanContext


@dataclass
class VendorResult:
    vendor: str
    product: str
    confidence: float
    evidence: list[str]


_VENDOR_PATTERNS = [
    ("Dell iDRAC", "iDRAC", ["idrac", "integrated dell remote access controller", "dell"]),
    ("HP iLO", "iLO", ["ilo", "hewlett packard enterprise", "hpe", " hp "]),
    ("Supermicro", "IPMI", ["supermicro", "aten", "megarac"]),
    ("Lenovo", "IMM/XClarity", ["imm", "xclarity", "lenovo"]),
    ("Cisco", "CIMC", ["cimc", "cisco integrated management controller"]),
]


class VendorClassifier:
    def classify(self, context: ScanContext) -> VendorResult | None:
        text_sources: list[tuple[str, str]] = []

        if context.ipmi_finding and context.ipmi_finding.vendor:
            text_sources.append(("IPMI MAC OUI", context.ipmi_finding.vendor.lower()))

        best: VendorResult | None = None
        best_confidence = 0.0

        for vendor, product, patterns in _VENDOR_PATTERNS:
            evidence = []
            for source_name, text in text_sources:
                for pat in patterns:
                    if pat in text:
                        evidence.append(f"{source_name} contains '{pat}'")

            if evidence:
                confidence = min(0.5 + 0.15 * len(evidence), 0.95)
                if confidence > best_confidence:
                    best_confidence = confidence
                    best = VendorResult(
                        vendor=vendor,
                        product=product,
                        confidence=confidence,
                        evidence=evidence,
                    )

        return best

    def apply_to_context(self, context: ScanContext) -> None:
        result = self.classify(context)
        if result and context.ipmi_finding:
            context.ipmi_finding.vendor = f"{result.vendor} {result.product}"
            context.ipmi_finding.vendor_confidence = result.confidence
