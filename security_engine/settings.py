"""
security_engine/settings.py — Configuration Foundation (Blueprint NFR-01, §3.3)

source of truth เดียวของค่าระบบคือ config/config.yaml — โมดูลอื่นไม่ต้องรู้จัก YAML
    config.yaml -> load_settings() -> Settings (typed) -> entry point -> components

precedence ที่ล็อกไว้:
    config.yaml  ->  environment override (เฉพาะค่าที่อนุญาต)  ->  ไม่มีค่า = ConfigError

ค่าที่มาจาก environment เท่านั้น (NFR-07 — ไม่เก็บใน repo):
    ITIS_PFSENSE_HOST   required ตอนรันจริง
    ITIS_EVE_PATH       optional — override eve.path ใน config.yaml

*** validate ตอนโหลด ไม่ใช่ตอนใช้ *** — ค่าเสียต้องพังพร้อมบอกว่า key ไหนเสีย
เพราะ config ที่ผิดเงียบ ๆ จะทำให้ผลการทดลองผิดโดยไม่มีใครรู้
"""
import os
from dataclasses import dataclass
from pathlib import Path

import yaml

# repo root = โฟลเดอร์แม่ของ security_engine/ — ยึดจากไฟล์นี้ ไม่ใช่ cwd
# (entry point ถูกเรียกจากที่ไหนก็ได้ แต่ config ต้องเป็นไฟล์เดียวกันเสมอ)
ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = ROOT / "config" / "config.yaml"

ENV_PFSENSE_HOST = "ITIS_PFSENSE_HOST"
ENV_EVE_PATH = "ITIS_EVE_PATH"

VALID_WEIGHT_SETS = ("A", "B", "C")
VALID_LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")


class ConfigError(Exception):
    """configuration ไม่ครบหรือไม่ถูกต้อง (ไฟล์หาย, key หาย, ค่าผิดชนิด/ผิดช่วง,
    หรือ environment variable ที่จำเป็นไม่ได้ตั้ง)"""


# ---------- environment ----------
def require_env(name: str) -> str:
    """อ่าน env ที่จำเป็น — ไม่มีหรือว่าง = พังทันที
    (fail fast ดีกว่าปล่อยให้ไป ssh ผิดเครื่อง/อ่านไฟล์ผิดตัวแล้วค่อยรู้)"""
    value = os.environ.get(name, "").strip()
    if not value:
        raise ConfigError(
            f"ต้องตั้ง environment variable {name} ก่อนรัน "
            f'(เช่น $env:{name} = "..." — ดูตัวอย่างใน .env.example)'
        )
    return value


def env_override(name: str) -> str:
    """env แบบ optional — ว่างหรือมีแต่ whitespace ถือว่าไม่ได้ตั้ง (คืน "")"""
    return os.environ.get(name, "").strip()


# ---------- typed configuration ----------
@dataclass(frozen=True)
class SystemConfig:
    db_path: str
    log_path: str
    log_level: str


@dataclass(frozen=True)
class EveConfig:
    path: str           # ว่างได้ตอนโหลด — required เฉพาะตอนจะอ่าน EVE จริง


@dataclass(frozen=True)
class CorrelationConfig:
    window_sec: int
    min_events: int


@dataclass(frozen=True)
class BlockConfig:
    duration_sec: int


@dataclass(frozen=True)
class HealthConfig:
    check_interval_sec: int
    stats_freshness_multiplier: int


@dataclass(frozen=True)
class RecoveryConfig:
    max_attempts: int


@dataclass(frozen=True)
class RiskConfig:
    weight_set: str


@dataclass(frozen=True)
class Settings:
    system: SystemConfig
    eve: EveConfig
    correlation: CorrelationConfig
    block: BlockConfig
    health: HealthConfig
    recovery: RecoveryConfig
    risk: RiskConfig

    def pfsense_host(self) -> str:
        """host ของ pfSense — environment เท่านั้น (NFR-07) ไม่มี = ConfigError"""
        return require_env(ENV_PFSENSE_HOST)

    def require_eve_path(self) -> str:
        """EVE path ที่ resolve แล้ว — ว่างทั้ง config และ env = ConfigError"""
        if not self.eve.path:
            raise ConfigError(
                f"ไม่มีค่า EVE path — ตั้ง eve.path ใน config/config.yaml "
                f"หรือ environment variable {ENV_EVE_PATH}"
            )
        return self.eve.path


# ---------- validation helpers ----------
def _section(data: dict, name: str) -> dict:
    value = data.get(name)
    if value is None:
        raise ConfigError(f"config ขาด section {name!r}")
    if not isinstance(value, dict):
        raise ConfigError(f"section {name!r} ต้องเป็น mapping ไม่ใช่ {type(value).__name__}")
    return value


def _require_int(section: dict, key: str, path: str, *, minimum: int) -> int:
    if key not in section:
        raise ConfigError(f"config ขาด key {path!r}")
    value = section[key]
    # bool เป็น subclass ของ int ใน Python — ต้องกันไว้ ไม่งั้น true จะกลายเป็น 1
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{path!r} ต้องเป็นจำนวนเต็ม ได้ {value!r}")
    if value < minimum:
        raise ConfigError(f"{path!r} ต้อง >= {minimum} ได้ {value!r}")
    return value


def _require_str(section: dict, key: str, path: str, *, allow_empty=False) -> str:
    if key not in section:
        raise ConfigError(f"config ขาด key {path!r}")
    value = section[key]
    if value is None and allow_empty:
        return ""
    if not isinstance(value, str):
        raise ConfigError(f"{path!r} ต้องเป็น string ได้ {value!r}")
    value = value.strip()
    if not value and not allow_empty:
        raise ConfigError(f"{path!r} ต้องไม่เป็นค่าว่าง")
    return value


# ---------- loader ----------
def load_settings(config_path=DEFAULT_CONFIG_PATH) -> Settings:
    """อ่าน config.yaml -> validate -> Settings (พร้อมใช้ env override แล้ว)"""
    path = Path(config_path)
    if not path.is_file():
        raise ConfigError(f"ไม่พบไฟล์ config: {path}")

    try:
        with path.open(encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as exc:
        raise ConfigError(f"config ไม่ใช่ YAML ที่ถูกต้อง ({path}): {exc}") from exc

    if not isinstance(data, dict):
        raise ConfigError(f"config ต้องเป็น mapping ที่ระดับบนสุด ({path})")

    system = _section(data, "system")
    eve = _section(data, "eve")
    correlation = _section(data, "correlation")
    block = _section(data, "block")
    health = _section(data, "health")
    recovery = _section(data, "recovery")
    risk = _section(data, "risk")

    log_level = _require_str(system, "log_level", "system.log_level").upper()
    if log_level not in VALID_LOG_LEVELS:
        raise ConfigError(
            f"system.log_level ต้องเป็นหนึ่งใน {VALID_LOG_LEVELS} ได้ {log_level!r}")

    weight_set = _require_str(risk, "weight_set", "risk.weight_set")
    if weight_set not in VALID_WEIGHT_SETS:
        raise ConfigError(
            f"risk.weight_set ต้องเป็นหนึ่งใน {VALID_WEIGHT_SETS} ได้ {weight_set!r}"
        )

    # ITIS_EVE_PATH ชนะค่าใน config.yaml — env ว่าง/whitespace = ไม่ได้ตั้ง (fallback)
    eve_path = env_override(ENV_EVE_PATH) or _require_str(
        eve, "path", "eve.path", allow_empty=True)

    return Settings(
        system=SystemConfig(
            db_path=_require_str(system, "db_path", "system.db_path"),
            log_path=_require_str(system, "log_path", "system.log_path"),
            log_level=log_level,
        ),
        eve=EveConfig(path=eve_path),
        correlation=CorrelationConfig(
            window_sec=_require_int(correlation, "window_sec",
                                    "correlation.window_sec", minimum=1),
            min_events=_require_int(correlation, "min_events",
                                    "correlation.min_events", minimum=1),
        ),
        block=BlockConfig(
            duration_sec=_require_int(block, "duration_sec",
                                      "block.duration_sec", minimum=1),
        ),
        health=HealthConfig(
            check_interval_sec=_require_int(health, "check_interval_sec",
                                            "health.check_interval_sec", minimum=1),
            stats_freshness_multiplier=_require_int(
                health, "stats_freshness_multiplier",
                "health.stats_freshness_multiplier", minimum=1),
        ),
        recovery=RecoveryConfig(
            max_attempts=_require_int(recovery, "max_attempts",
                                      "recovery.max_attempts", minimum=1),
        ),
        risk=RiskConfig(weight_set=weight_set),
    )
