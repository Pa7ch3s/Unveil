"""
Configurable limits and logging. Values can be overridden by environment or by run() options.
"""
import os
import json as _json

# Defaults
DEFAULT_MAX_FILES = 80
DEFAULT_MAX_SIZE_MB = 120
DEFAULT_MAX_PER_TYPE = 500
DEFAULT_REF_EXTRACT_MAX_SIZE = 512 * 1024  # 512KB
DEFAULT_REF_EXTRACT_MAX_FILES = 100

# Env keys
ENV_MAX_FILES = "UNVEIL_MAX_FILES"
ENV_MAX_SIZE_MB = "UNVEIL_MAX_SIZE_MB"
ENV_MAX_PER_TYPE = "UNVEIL_MAX_PER_TYPE"
ENV_REF_EXTRACT_MAX_FILES = "UNVEIL_REF_EXTRACT_MAX_FILES"
ENV_LOG = "UNVEIL_LOG"  # 1 or "1" to enable structured log to stderr
ENV_VERBOSE = "UNVEIL_VERBOSE"  # same as UNVEIL_LOG for compatibility


def _int_env(name, default):
    try:
        v = os.environ.get(name)
        if v is not None:
            return int(v)
    except ValueError:
        pass
    return default


def get_max_files(override=None):
    return override if override is not None else _int_env(ENV_MAX_FILES, DEFAULT_MAX_FILES)


def get_max_size_bytes(override_mb=None):
    if override_mb is not None:
        return override_mb * 1024 * 1024
    mb = _int_env(ENV_MAX_SIZE_MB, DEFAULT_MAX_SIZE_MB)
    return mb * 1024 * 1024


def get_max_per_type(override=None):
    return override if override is not None else _int_env(ENV_MAX_PER_TYPE, DEFAULT_MAX_PER_TYPE)


def get_ref_extract_max_files(override=None):
    return (
        override
        if override is not None
        else _int_env(ENV_REF_EXTRACT_MAX_FILES, DEFAULT_REF_EXTRACT_MAX_FILES)
    )


def logging_enabled(override=None):
    if override is not None:
        return bool(override)
    return os.environ.get(ENV_LOG, "").strip() in ("1", "true", "yes") or os.environ.get(
        ENV_VERBOSE, ""
    ).strip() in ("1", "true", "yes")


def log(level, msg, **kwargs):
    """Write a single JSON line to stderr if UNVEIL_LOG=1 or UNVEIL_VERBOSE=1."""
    if not logging_enabled():
        return
    try:
        line = _json.dumps({"level": level, "message": msg, **kwargs})
        import sys
        sys.stderr.write(line + "\n")
        sys.stderr.flush()
    except Exception:
        pass
