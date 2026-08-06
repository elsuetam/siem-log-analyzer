"""Catálogo estático de técnicas MITRE ATT&CK referenciadas pelos detectores.

Cobre apenas as técnicas relevantes aos detectores implementados neste
projeto — não é uma cópia completa da matriz ATT&CK. Para a referência
completa e atualizada, ver https://attack.mitre.org/.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class MitreTechnique:
    """Uma técnica do framework MITRE ATT&CK."""

    technique_id: str
    name: str
    tactic: str
    url: str


BRUTE_FORCE = MitreTechnique(
    technique_id="T1110",
    name="Brute Force",
    tactic="Credential Access",
    url="https://attack.mitre.org/techniques/T1110/",
)

ACTIVE_SCANNING = MitreTechnique(
    technique_id="T1595",
    name="Active Scanning",
    tactic="Reconnaissance",
    url="https://attack.mitre.org/techniques/T1595/",
)

EXPLOIT_PUBLIC_FACING_APPLICATION = MitreTechnique(
    technique_id="T1190",
    name="Exploit Public-Facing Application",
    tactic="Initial Access",
    url="https://attack.mitre.org/techniques/T1190/",
)