"""Unit tests for ffuf-auto's pure logic (no network, no ffuf binary needed)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ffuf_auto import (  # noqa: E402
    Finding,
    PreflightError,
    ScanConfig,
    build_command,
    config_from_args,
    parse_args,
    preflight,
)


@pytest.fixture
def cfg(tmp_path: Path) -> ScanConfig:
    subs = tmp_path / "subs.txt"
    dirs = tmp_path / "dirs.txt"
    subs.write_text("admin\ndev\n")
    dirs.write_text("robots.txt\nadmin\n")
    return ScanConfig(
        host="target.htb",
        wordlists={"subdomain": subs, "directory": dirs},
        output_dir=tmp_path / "results",
    )


# --- build_command --------------------------------------------------------- #


def test_vhost_sets_host_header(cfg: ScanConfig) -> None:
    cmd = build_command(cfg, "vhost")
    assert "-H" in cmd
    assert cmd[cmd.index("-H") + 1] == "Host: FUZZ.target.htb"
    assert cmd[cmd.index("-u") + 1] == "http://target.htb/"


def test_subdomain_fuzzes_the_hostname(cfg: ScanConfig) -> None:
    cmd = build_command(cfg, "subdomain")
    assert cmd[cmd.index("-u") + 1] == "http://FUZZ.target.htb/"
    assert "-H" not in cmd


def test_directory_fuzzes_the_path(cfg: ScanConfig) -> None:
    cmd = build_command(cfg, "directory")
    assert cmd[cmd.index("-u") + 1] == "http://target.htb/FUZZ"
    assert cmd[cmd.index("-w") + 1].endswith("dirs.txt")


def test_https_and_custom_port(cfg: ScanConfig) -> None:
    cfg.scheme, cfg.port = "https", 8443
    assert build_command(cfg, "directory")[6] == "https://target.htb:8443/FUZZ"
    vhost = build_command(cfg, "vhost")
    assert vhost[vhost.index("-H") + 1] == "Host: FUZZ.target.htb:8443"


def test_default_port_is_omitted(cfg: ScanConfig) -> None:
    cfg.scheme, cfg.port = "https", 443
    assert cfg.base_url == "https://target.htb"


def test_size_filter_only_applies_to_its_own_scan(cfg: ScanConfig) -> None:
    cfg.filter_size = {"vhost": 400}
    assert "-fs" in build_command(cfg, "vhost")
    assert "-fs" not in build_command(cfg, "subdomain")


def test_passthrough_flags_are_appended(cfg: ScanConfig) -> None:
    cfg.auto_calibrate = True
    cfg.match_codes = "200,301"
    cfg.rate = 50
    cfg.extra = ["-e", ".php"]
    cmd = build_command(cfg, "directory")
    assert "-ac" in cmd
    assert cmd[cmd.index("-mc") + 1] == "200,301"
    assert cmd[cmd.index("-rate") + 1] == "50"
    assert cmd[-2:] == ["-e", ".php"]


def test_unknown_scan_type_raises(cfg: ScanConfig) -> None:
    with pytest.raises(ValueError):
        build_command(cfg, "banana")


# --- preflight ------------------------------------------------------------- #


def test_preflight_rejects_missing_wordlist(cfg: ScanConfig, monkeypatch) -> None:
    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/ffuf")
    cfg.wordlists["subdomain"] = Path("/nope/does-not-exist.txt")
    with pytest.raises(PreflightError, match="does not exist"):
        preflight(cfg)


def test_preflight_rejects_empty_wordlist(cfg: ScanConfig, monkeypatch, tmp_path) -> None:
    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/ffuf")
    empty = tmp_path / "empty.txt"
    empty.touch()
    cfg.wordlists["directory"] = empty
    with pytest.raises(PreflightError, match="empty"):
        preflight(cfg)


def test_preflight_rejects_missing_ffuf(cfg: ScanConfig, monkeypatch) -> None:
    monkeypatch.setattr("shutil.which", lambda _: None)
    with pytest.raises(PreflightError, match="ffuf"):
        preflight(cfg)


def test_preflight_skips_unused_wordlists(cfg: ScanConfig, monkeypatch) -> None:
    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/ffuf")
    cfg.scans = ("directory",)
    cfg.wordlists["subdomain"] = Path("/nope/does-not-exist.txt")
    preflight(cfg)  # must not raise


# --- rendering safety ------------------------------------------------------ #


def test_bracketed_status_is_escaped_not_parsed_as_markup() -> None:
    line = Finding("directory", "http://t/[weird]", "[weird]", 404, 12, 3, 1).as_line()
    assert "\\[404]" in line
    assert "\\[weird]" in line


# --- CLI ------------------------------------------------------------------- #


def test_cli_maps_filters_to_scan_names() -> None:
    cfg = config_from_args(parse_args(["target.htb", "-fsV", "400", "-fsD", "12"]))
    assert cfg.filter_size == {"vhost": 400, "directory": 12}


def test_cli_deduplicates_scan_selection() -> None:
    cfg = config_from_args(parse_args(["target.htb", "--scans", "vhost", "vhost"]))
    assert cfg.scans == ("vhost",)
