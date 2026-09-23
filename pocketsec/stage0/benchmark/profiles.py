"""Resource profiles (spec section 14).

These are **research targets to test, not promised numbers**. The checker
therefore reports observations; it never silently passes a run, and it never
converts an unmeasured field into a pass.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from pocketsec.stage0.benchmark.resource_metrics import ResourceMetrics

__all__ = ["PROFILES", "ProfileReport", "ResourceProfile", "check_profile"]

_MB = 1024 * 1024


@dataclass(frozen=True, slots=True)
class ResourceProfile:
    name: str
    agent_rss_target_bytes: int
    model_bytes_target: int | None
    purpose: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "agent_rss_target_bytes": self.agent_rss_target_bytes,
            "model_bytes_target": self.model_bytes_target,
            "purpose": self.purpose,
        }


PROFILES: dict[str, ResourceProfile] = {
    "nano": ResourceProfile(
        name="nano",
        agent_rss_target_bytes=50 * _MB,
        model_bytes_target=5 * _MB,
        purpose="Extreme low-spec / embedded research target",
    ),
    "edge": ResourceProfile(
        name="edge",
        agent_rss_target_bytes=100 * _MB,
        model_bytes_target=25 * _MB,
        purpose="Primary PocketSec target",
    ),
    "research_max": ResourceProfile(
        name="research_max",
        agent_rss_target_bytes=200 * _MB,
        model_bytes_target=None,
        purpose="Higher-capability experimental ceiling",
    ),
}

#: The hard system constraint the deployed agent shares the host with.
HOST_RAM_TARGET_BYTES = 2 * 1024 * _MB


@dataclass(frozen=True, slots=True)
class ProfileReport:
    profile: str
    observations: tuple[str, ...]
    exceeded: tuple[str, ...]
    unmeasured: tuple[str, ...]

    @property
    def within_target(self) -> bool | None:
        """``None`` when nothing could be measured — not ``True``."""
        if self.unmeasured and not self.exceeded:
            return None
        return not self.exceeded

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile": self.profile,
            "within_target": self.within_target,
            "observations": list(self.observations),
            "exceeded": list(self.exceeded),
            "unmeasured": list(self.unmeasured),
        }


def check_profile(
    metrics: ResourceMetrics, profile_name: str, *, model_bytes: int | None = None
) -> ProfileReport:
    """Compare a measured run against a profile's targets."""
    profile = PROFILES.get(profile_name)
    if profile is None:
        raise KeyError(f"unknown resource profile {profile_name!r}; known: {sorted(PROFILES)}")

    observations: list[str] = []
    exceeded: list[str] = []
    unmeasured: list[str] = []

    observed_rss = metrics.peak_sampled_rss_bytes or metrics.peak_rss_bytes
    if observed_rss is None:
        unmeasured.append("agent_rss")
    else:
        observations.append(f"peak agent RSS {observed_rss / _MB:.1f} MB")
        if observed_rss > profile.agent_rss_target_bytes:
            exceeded.append(
                f"agent_rss {observed_rss / _MB:.1f} MB > "
                f"{profile.agent_rss_target_bytes / _MB:.0f} MB target"
            )

    if profile.model_bytes_target is None:
        observations.append("model size target: flexible for this profile")
    elif model_bytes is None:
        unmeasured.append("model_bytes")
    else:
        observations.append(f"model size {model_bytes / _MB:.2f} MB")
        if model_bytes > profile.model_bytes_target:
            exceeded.append(
                f"model_bytes {model_bytes / _MB:.2f} MB > "
                f"{profile.model_bytes_target / _MB:.0f} MB target"
            )

    return ProfileReport(
        profile=profile.name,
        observations=tuple(observations),
        exceeded=tuple(exceeded),
        unmeasured=tuple(unmeasured),
    )
