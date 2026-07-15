#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Verify the locked Dioxus diagnostic runtime and its transport boundary."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any


DIOXUS_VERSION = "0.7.9"
LOOPBACK_BIND = "TcpListener::bind((IpAddr::from([127, 0, 0, 1]), 0))"
LOOPBACK_URL = "ws://127.0.0.1:{port}/{webview_id}/{key_hex}"
MUTUAL_KEY_SIZE = "const KEY_SIZE: usize = 256;"
CLIENT_KEY = "client_key: [u8; KEY_SIZE],"
SERVER_KEY = "server_key: [u8; KEY_SIZE],"
SECURE_KEY_CREATION = "rand::rngs::StdRng::from_os_rng()"
CONSTANT_TIME_COMPARE = "subtle::ConstantTimeEq::ct_eq("
SERVER_KEY_RESPONSE = ".send(tungstenite::Message::Text(hex_encoded_server_key.into()))"
HANDSHAKE_LIMIT = "const DEFAULT_HANDSHAKE_LIMIT: usize = 8;"
HANDSHAKE_TIMEOUT = "const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(1);"
HANDSHAKE_SLOT = "struct HandshakeSlot(Arc<HandshakeSlots>);"
HANDSHAKE_REJECTION = "stream.shutdown(Shutdown::Both)"
ABSOLUTE_HANDSHAKE_DEADLINE = "struct HandshakeStream {"
HANDSHAKE_DEADLINE_REMAINING = "checked_duration_since(Instant::now())"
HANDSHAKE_DEADLINE_CLEAR = "fn finish_handshake(&mut self) -> io::Result<()>"
GENERATION = "generation: u64,"
LISTENER_GENERATION_CAPTURE = "let accepted_location = listener_location;"
GENERATION_CHECK = "if *active_server_location != current_server_location"
GENERATION_INCREMENT = '.checked_add(1)\n                .expect("WebSocket listener generation exhausted")'
GENERATION_TEARDOWN = "fn transition_to_pending_if_generation("
SERVER_KEY_FAILURE = "Webview {} closed during server-key authentication"
EXPLICIT_EDIT_ACK = "Ok(tungstenite::Message::Binary(_)) => break,"
EDIT_DISCONNECT = "disconnected before acknowledging edits"
LOSSLESS_TEARDOWN_DRAIN = "while let Ok(msg) = edits_incoming_rx.try_recv()"
SLOW_DRIP_TEST = "fn slow_drip_upgrade_cannot_extend_the_handshake_deadline()"
PRODUCTION_ROTATION_TEST = "fn stale_handshake_is_rejected_after_listener_generation_rotation()"
DEVTOOLS_MATCH_ARM_GUARD = '#[cfg(debug_assertions)]\n            "dioxus-toggle-dev-tools" => {'
DEVTOOLS_FIELD_GUARD = "#[cfg(debug_assertions)]\n    pub(crate) show_devtools: bool,"
DEVTOOLS_INITIALIZER_GUARD = "#[cfg(debug_assertions)]\n            show_devtools: false,"
MENUBAR_DEVTOOLS_GUARD = "#[cfg(debug_assertions)]\n        {\n            let help_menu = Submenu::new(\"Help\", true);"


APPLE_TARGETS = (
    "aarch64-apple-darwin",
    "aarch64-apple-ios",
    "aarch64-apple-ios-sim",
)
NON_APPLE_UNMAINTAINED_PACKAGE_NAMES = {
    "atk",
    "atk-sys",
    "fxhash",
    "gdk",
    "gdk-sys",
    "gdkwayland-sys",
    "gdkx11-sys",
    "gtk",
    "gtk-sys",
    "gtk3-macros",
    "proc-macro-error",
}


def semver_triplet(version: str) -> tuple[int, int, int]:
    core = version.split("-", maxsplit=1)[0]
    parts = core.split(".")
    if len(parts) != 3:
        raise SystemExit(f"Expected a three-part semantic version, found {version!r}")
    major, minor, patch = (int(part) for part in parts)
    return major, minor, patch


def has_ignored_non_apple_advisory(name: str, version: str) -> bool:
    if name in NON_APPLE_UNMAINTAINED_PACKAGE_NAMES:
        return True
    if name == "glib":
        parsed = semver_triplet(version)
        return (0, 15, 0) <= parsed < (0, 20, 0)
    if name == "rand":
        parsed = semver_triplet(version)
        return (0, 7, 0) <= parsed < (0, 8, 6) or (
            (0, 9, 0) <= parsed < (0, 9, 3)
        )
    return False


def cargo_metadata(workspace: Path, target: str) -> dict[str, Any]:
    command = [
        "cargo",
        "metadata",
        "--format-version",
        "1",
        "--filter-platform",
        target,
        "--locked",
        "--offline",
    ]
    result = subprocess.run(
        command,
        cwd=workspace,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def package(metadata: dict[str, Any], name: str) -> dict[str, Any]:
    matches = [item for item in metadata["packages"] if item["name"] == name]
    if len(matches) != 1:
        raise SystemExit(f"Expected one resolved {name} package, found {len(matches)}")
    return matches[0]


def resolved_features(
    metadata: dict[str, Any], package_id: str, package_name: str
) -> set[str]:
    resolve = metadata.get("resolve")
    if resolve is None:
        raise SystemExit("Cargo metadata did not include a dependency resolution")
    matches = [node for node in resolve["nodes"] if node["id"] == package_id]
    if len(matches) != 1:
        raise SystemExit(f"{package_name} is missing from the resolved dependency graph")
    return set(matches[0]["features"])


def resolved_packages(metadata: dict[str, Any]) -> set[tuple[str, str]]:
    resolve = metadata.get("resolve")
    if resolve is None:
        raise SystemExit("Cargo metadata did not include a dependency resolution")
    node_ids = {node["id"] for node in resolve["nodes"]}
    return {
        (item["name"], item["version"])
        for item in metadata["packages"]
        if item["id"] in node_ids
    }


def require_ordered_markers(source: str, markers: tuple[str, ...], label: str) -> None:
    positions = [source.find(marker) for marker in markers]
    if any(position < 0 for position in positions) or positions != sorted(positions):
        raise SystemExit(f"Dioxus {label} invariant changed: expected ordered markers {markers!r}")


def main() -> None:
    workspace = Path(__file__).resolve().parents[2]
    subprocess.run(
        ["python3", str(workspace / "apple" / "scripts" / "verify-dioxus-vendor.py")],
        check=True,
    )
    metadata_by_target = {
        target: cargo_metadata(workspace, target) for target in APPLE_TARGETS
    }
    for target, target_metadata in metadata_by_target.items():
        reachable = {
            (name, version)
            for name, version in resolved_packages(target_metadata)
            if has_ignored_non_apple_advisory(name, version)
        }
        if reachable:
            raise SystemExit(
                f"Non-Apple advisory packages became reachable from {target}: "
                f"{sorted(reachable)}"
            )

    ios_device_packages = resolved_packages(metadata_by_target["aarch64-apple-ios"])
    ios_simulator_packages = resolved_packages(
        metadata_by_target["aarch64-apple-ios-sim"]
    )
    if ios_device_packages != ios_simulator_packages:
        raise SystemExit(
            "The shared iOS notice cannot cover different device and simulator graphs"
        )

    for target, metadata in metadata_by_target.items():
        names = {item["name"] for item in metadata["packages"]}
        forbidden = names.intersection({"manganis", "dioxus-devtools", "dioxus-web"})
        if forbidden:
            raise SystemExit(
                f"Forbidden Dioxus runtime packages are resolved for {target}: "
                f"{sorted(forbidden)}"
            )

        dioxus = package(metadata, "dioxus")
        desktop = package(metadata, "dioxus-desktop")
        if dioxus["version"] != DIOXUS_VERSION or desktop["version"] != DIOXUS_VERSION:
            raise SystemExit(f"The Dioxus graph for {target} is not pinned to 0.7.9")

        features = resolved_features(metadata, desktop["id"], "Dioxus Desktop")
        if features != {"tokio_runtime"}:
            raise SystemExit(
                "Dioxus Desktop must enable only its required tokio_runtime "
                f"feature for {target}; resolved {sorted(features)}"
            )

        wry = package(metadata, "wry")
        wry_features = resolved_features(metadata, wry["id"], "Wry")
        if "devtools" in wry_features:
            raise SystemExit(
                f"Wry devtools must be absent for {target}; resolved {sorted(wry_features)}"
            )

        dioxus_features = resolved_features(metadata, dioxus["id"], "Dioxus")
        expected_dioxus_features = {"hooks", "html", "macro", "signals"}
        if dioxus_features != expected_dioxus_features:
            raise SystemExit(
                "The Dioxus facade must keep its minimal diagnostic feature set "
                f"for {target}; resolved {sorted(dioxus_features)}"
            )

    metadata = metadata_by_target["aarch64-apple-darwin"]
    desktop = package(metadata, "dioxus-desktop")
    source = Path(desktop["manifest_path"]).parent
    edits = (source / "src" / "edits.rs").read_text(encoding="utf-8")
    transport_markers = (
        LOOPBACK_BIND,
        LOOPBACK_URL,
        MUTUAL_KEY_SIZE,
        CLIENT_KEY,
        SERVER_KEY,
        SECURE_KEY_CREATION,
        CONSTANT_TIME_COMPARE,
        SERVER_KEY_RESPONSE,
        HANDSHAKE_LIMIT,
        HANDSHAKE_TIMEOUT,
        HANDSHAKE_SLOT,
        HANDSHAKE_REJECTION,
        ABSOLUTE_HANDSHAKE_DEADLINE,
        HANDSHAKE_DEADLINE_REMAINING,
        HANDSHAKE_DEADLINE_CLEAR,
        GENERATION,
        LISTENER_GENERATION_CAPTURE,
        GENERATION_CHECK,
        GENERATION_INCREMENT,
        GENERATION_TEARDOWN,
        SERVER_KEY_FAILURE,
        EXPLICIT_EDIT_ACK,
        EDIT_DISCONNECT,
        LOSSLESS_TEARDOWN_DRAIN,
        SLOW_DRIP_TEST,
        PRODUCTION_ROTATION_TEST,
    )
    for marker in transport_markers:
        if marker not in edits:
            raise SystemExit(f"Dioxus transport invariant changed: missing {marker!r}")
    transport_tests = edits.split("mod transport_tests {", maxsplit=1)
    if len(transport_tests) != 2 or "#[ignore" in transport_tests[1]:
        raise SystemExit("Dioxus live transport tests must exist and must not be ignored")
    if "set_read_timeout(Some(handshake_timeout))" in edits:
        raise SystemExit("Dioxus handshakes must use an absolute deadline, not an inactivity timeout")

    cargo_toml = (workspace / "Cargo.toml").read_text(encoding="utf-8")
    if 'dioxus-desktop = { path = "vendor/dioxus-desktop-0.7.9" }' not in cargo_toml:
        raise SystemExit("Dioxus local patch pin is missing")

    config = (source / "src" / "config.rs").read_text(encoding="utf-8")
    webview = (source / "src" / "webview.rs").read_text(encoding="utf-8")
    app_runtime = (source / "src" / "app.rs").read_text(encoding="utf-8")
    menubar_runtime = (source / "src" / "menubar.rs").read_text(encoding="utf-8")
    launch_runtime = (source / "src" / "launch.rs").read_text(encoding="utf-8")
    desktop_runtime = config + webview + app_runtime + launch_runtime
    required_desktop_markers = (
        "pub fn with_incognito(mut self, incognito: bool) -> Self",
        "pub(crate) incognito: bool,",
        ".with_incognito(incognito)",
        "pub(crate) fn navigation_decision(",
        "NavigationDecision::OpenExternal",
        "fn open_external_if_allowed<E>(",
        "pub(crate) navigation_handler: Option<NavigationHandler>,",
        "let ipc_navigation_handler = navigation_handler.clone();",
        "navigation_handler: ipc_navigation_handler,",
        "pub fn handle_browser_open(&mut self, msg: IpcMessage, id: WindowId)",
        ".map(|(window_id, webview)| (window_id, webview.navigation_handler.as_ref()))",
        "fn handle_browser_open_for_windows<'a, K: PartialEq + 'a, E>(",
        ".find_map(|(window_id, handler)| (window_id == originating_window).then_some(handler))",
        "IpcMethod::BrowserOpen => app.handle_browser_open(msg, id)",
        "browser_open_uses_originating_window_policy_and_unknown_ids_fail_closed",
    )
    for marker in required_desktop_markers:
        if marker not in desktop_runtime:
            raise SystemExit(f"Dioxus local patch invariant changed: missing {marker!r}")
    for marker in (
        DEVTOOLS_MATCH_ARM_GUARD,
        DEVTOOLS_FIELD_GUARD,
        DEVTOOLS_INITIALIZER_GUARD,
    ):
        if marker not in app_runtime:
            raise SystemExit(f"Dioxus Release devtools guard changed: missing {marker!r}")
    if MENUBAR_DEVTOOLS_GUARD not in menubar_runtime:
        raise SystemExit("Dioxus Release menubar guard changed: missing compile-time cfg")
    if "if cfg!(debug_assertions)" in menubar_runtime:
        raise SystemExit("Dioxus Release menubar must use a compile-time debug guard")
    forbidden_desktop_markers = (
        "IpcMethod::BrowserOpen => app.handle_browser_open(msg),",
        "pub(crate) navigation_handler: Option<NavigationHandler>,",
    )
    if forbidden_desktop_markers[0] in launch_runtime:
        raise SystemExit("Dioxus browser-open IPC no longer carries its window ID")
    if forbidden_desktop_markers[1] in app_runtime:
        raise SystemExit("Dioxus navigation policy must be stored per WebView, not per App")
    require_ordered_markers(
        webview,
        (
            "if is_dioxus_internal_url(url)",
            "if let Some(handler) = navigation_handler",
            "if is_external_browser_url(url)",
        ),
        "navigation decision ordering",
    )

    wry = package(metadata, "wry")
    wry_source = Path(wry["manifest_path"]).parent
    wry_webview = (wry_source / "src" / "wkwebview" / "mod.rs").read_text(encoding="utf-8")
    if "WKWebsiteDataStore::nonPersistentDataStore" not in wry_webview:
        raise SystemExit("Wry non-persistent WKWebsiteDataStore invariant changed")

    app = (workspace / "apps" / "dioxus-spike" / "src" / "main.rs").read_text(
        encoding="utf-8"
    )
    required_app_markers = (
        ".with_incognito(true)",
        ".with_navigation_handler(|url| {",
        "TERSA-DIOXUS-NAV-DENIED",
        "localStorage.setItem('tersa-dioxus-ephemeral-probe', 'written')",
        "document.cookie = 'tersa-dioxus-ephemeral-cookie=written; SameSite=Strict'",
        "window.location.assign('https://example.invalid/location')",
        "window.open('https://example.invalid/window-open', '_blank')",
        "https://example.invalid/ipc-browser-open",
        "LOCAL STORAGE ABSENT AFTER RELAUNCH",
        "COOKIE API UNAVAILABLE ON DIOXUS SCHEME",
        "WINDOW OPEN REJECTED",
        ".with_custom_index(INDEX.to_owned())",
        '<html lang="en">',
        "<title>tersa.app — Dioxus M0 diagnostic</title>",
        "TERSA-DIOXUS-M0-THREAD",
        "TERSA_DIOXUS_EVIDENCE",
        '"data-expected-rows": "{rendered_rows}"',
        "new MutationObserver(updateActualRows)",
        "viewport-fit=cover",
        "const INBOX_ROWS: usize = 10_000;",
    )
    for marker in required_app_markers:
        if marker not in app:
            raise SystemExit(f"Dioxus application policy changed: missing {marker!r}")
    if "href:" in app or re.search(r"(?m)^\s*a\s*\{", app):
        raise SystemExit("External navigation elements are forbidden in the diagnostic UI")

    print("Dioxus runtime and loopback transport policy passed.")


if __name__ == "__main__":
    main()
