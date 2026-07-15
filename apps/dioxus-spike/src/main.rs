// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Runs the Apple-only Dioxus `WebView` diagnostic interface.

#![forbid(unsafe_code)]

#[cfg(any(target_os = "macos", target_os = "ios"))]
#[allow(
    clippy::same_name_method,
    reason = "The Dioxus component macro generates a Props builder method"
)]
mod apple {
    use dioxus::prelude::*;
    use dioxus_desktop::Config;
    #[cfg(target_os = "macos")]
    use dioxus_desktop::{LogicalSize, WindowBuilder};

    const INBOX_ROWS: usize = 10_000;
    const ROW_HEIGHT_PX: f64 = 76.0;
    const OVERSCAN_ROWS: usize = 6;
    const MAX_RENDERED_ROWS: usize = 100;
    const STYLE: &str = include_str!("style.css");
    const INDEX: &str = r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>tersa.app — Dioxus M0 diagnostic</title>
</head>
<body>
  <div id="main"></div>
</body>
</html>"#;
    const VIRTUALIZER_SCRIPT: &str = r#"
        (() => {
            const install = () => {
                const list = document.querySelector('[data-evidence="virtual-list"]');
                if (!list) {
                    window.setTimeout(install, 0);
                    return;
                }

                window.__tersaVirtualizerResizeObserver?.disconnect();
                window.__tersaVirtualizerMutationObserver?.disconnect();
                const updateActualRows = () => {
                    const generation = (window.__tersaActualRowsGeneration ?? 0) + 1;
                    window.__tersaActualRowsGeneration = generation;
                    let attempts = 0;
                    const settle = () => window.requestAnimationFrame(() => {
                        if (generation !== window.__tersaActualRowsGeneration) {
                            return;
                        }
                        const currentList = document.querySelector(
                            '[data-evidence="virtual-list"]'
                        );
                        const output = document.querySelector(
                            '[data-evidence="actual-dom-rows"]'
                        );
                        if (!currentList || !output) {
                            return;
                        }
                        const expected = Number(currentList.dataset.expectedRows);
                        const actual = document.querySelectorAll('.mail-row').length;
                        if (actual !== expected && attempts < 120) {
                            attempts += 1;
                            settle();
                            return;
                        }
                        output.textContent = actual === expected
                            ? `ACTUAL DOM ROWS ${actual}`
                            : `ACTUAL DOM ROWS UNSETTLED ${actual} OF ${expected}`;
                    });
                    settle();
                };
                const notify = () => {
                    list.dispatchEvent(new Event('scroll', { bubbles: true }));
                    updateActualRows();
                };
                const observer = new ResizeObserver(notify);
                observer.observe(list);
                const mutationObserver = new MutationObserver(updateActualRows);
                mutationObserver.observe(list, {
                    attributes: true,
                    attributeFilter: ['data-expected-rows'],
                    childList: true,
                    subtree: true,
                });
                list.addEventListener('scroll', updateActualRows, { passive: true });
                window.__tersaVirtualizerResizeObserver = observer;
                window.__tersaVirtualizerMutationObserver = mutationObserver;
                notify();
            };
            install();
        })();
    "#;
    const JUMP_SCRIPT: &str = r#"
        (() => {
            const list = document.querySelector('[data-evidence="virtual-list"]');
            if (!list) {
                throw new Error('Dioxus virtual list is missing');
            }
            list.scrollTo({ top: 7600, behavior: 'auto' });
        })();
    "#;
    const EVIDENCE_SCRIPT: &str = r#"
        window.setTimeout(() => {
            const editor = document.querySelector('[data-evidence="composer"]');
            const advance = document.querySelector('[data-evidence="advance-list"]');
            const navigation = document.querySelector('[data-evidence="navigation"]');
            const storage = document.querySelector('[data-evidence="storage"]');
            const cookie = document.querySelector('[data-evidence="cookie"]');
            const popup = document.querySelector('[data-evidence="popup"]');
            if (!editor || !advance || !navigation || !storage || !cookie || !popup) {
                throw new Error('Dioxus evidence controls are missing');
            }
            const initialLocation = window.location.href;
            localStorage.setItem('tersa-dioxus-ephemeral-probe', 'written');
            document.cookie = 'tersa-dioxus-ephemeral-cookie=written; SameSite=Strict';
            const localStorageWritten =
                localStorage.getItem('tersa-dioxus-ephemeral-probe') === 'written';
            const cookieWritten = document.cookie.includes(
                'tersa-dioxus-ephemeral-cookie=written'
            );
            const anchor = document.createElement('a');
            anchor.setAttribute('href', 'https://example.invalid/anchor');
            anchor.textContent = 'Synthetic navigation probe';
            document.body.append(anchor);
            anchor.click();
            const ipcParams = {};
            ipcParams['href'] = 'https://example.invalid/ipc-browser-open';
            window.ipc.postMessage(JSON.stringify({
                method: 'browser_open',
                params: ipcParams
            }));
            const popupRejected =
                window.open('https://example.invalid/window-open', '_blank') === null;
            advance.click();
            window.setTimeout(() => {
                const setter = Object.getOwnPropertyDescriptor(
                    HTMLTextAreaElement.prototype,
                    'value'
                ).set;
                setter.call(
                    editor,
                    'TERSA DIOXUS INPUT ONE\nTERSA DIOXUS INPUT TWO'
                );
                editor.dispatchEvent(new Event('input', { bubbles: true }));
                const locationState = window.location.href === initialLocation
                    ? 'NAVIGATION PROBE PAGE UNCHANGED'
                    : 'NAVIGATION PROBE PAGE CHANGED';
                const storageState = localStorageWritten
                    ? 'LOCAL STORAGE WRITTEN'
                    : 'LOCAL STORAGE WRITE FAILED';
                const cookieState = cookieWritten
                    ? 'COOKIE WRITTEN'
                    : 'COOKIE API UNAVAILABLE ON DIOXUS SCHEME';
                const popupState = popupRejected
                    ? 'WINDOW OPEN REJECTED'
                    : 'WINDOW OPEN RETURNED A HANDLE';
                navigation.textContent = locationState;
                storage.textContent = storageState;
                cookie.textContent = cookieState;
                popup.textContent = popupState;
                window.setTimeout(() => {
                    window.location.assign('https://example.invalid/location');
                }, 15000);
            }, 250);
        }, 5000);
    "#;
    const RELAUNCH_EVIDENCE_SCRIPT: &str = r#"
        window.setTimeout(() => {
            const navigation = document.querySelector('[data-evidence="navigation"]');
            const storage = document.querySelector('[data-evidence="storage"]');
            const cookie = document.querySelector('[data-evidence="cookie"]');
            if (!navigation || !storage || !cookie) {
                throw new Error('Dioxus relaunch evidence control is missing');
            }
            const storageAbsent =
                localStorage.getItem('tersa-dioxus-ephemeral-probe') === null;
            document.cookie = 'tersa-dioxus-relaunch-cookie=probe; SameSite=Strict';
            const cookieApiAvailable = document.cookie.includes(
                'tersa-dioxus-relaunch-cookie=probe'
            );
            const storageState = storageAbsent
                ? 'LOCAL STORAGE ABSENT AFTER RELAUNCH'
                : 'LOCAL STORAGE PRESENT AFTER RELAUNCH';
            const cookieState = cookieApiAvailable
                ? 'COOKIE API AVAILABLE AFTER RELAUNCH'
                : 'COOKIE API UNAVAILABLE ON DIOXUS SCHEME';
            navigation.textContent = 'EPHEMERAL RELAUNCH PROBE';
            storage.textContent = storageState;
            cookie.textContent = cookieState;
        }, 1000);
    "#;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum SandboxProbe {
        Anchor,
        Ipc,
        Location,
    }

    impl SandboxProbe {
        const fn name(self) -> &'static str {
            match self {
                Self::Anchor => "ANCHOR",
                Self::Ipc => "IPC",
                Self::Location => "LOCATION",
            }
        }

        const fn denial_url(self) -> &'static str {
            match self {
                Self::Anchor => "https://example.invalid/anchor",
                Self::Ipc => "https://example.invalid/ipc-browser-open",
                Self::Location => "https://example.invalid/location",
            }
        }
    }

    /// Maps the evidence-only environment to one isolated sandbox diagnostic.
    fn sandbox_probe_from_env(
        evidence: Option<&std::ffi::OsStr>,
        probe: Option<&std::ffi::OsStr>,
    ) -> Result<Option<SandboxProbe>, &'static str> {
        let Some(probe) = probe else {
            return Ok(None);
        };
        if evidence.is_none() {
            return Err("TERSA_DIOXUS_SANDBOX_PROBE requires TERSA_DIOXUS_EVIDENCE");
        }
        match probe.to_str() {
            Some("anchor") => Ok(Some(SandboxProbe::Anchor)),
            Some("ipc") => Ok(Some(SandboxProbe::Ipc)),
            Some("location") => Ok(Some(SandboxProbe::Location)),
            _ => Err("TERSA_DIOXUS_SANDBOX_PROBE must be anchor, ipc, or location"),
        }
    }

    fn sandbox_probe_script(probe: SandboxProbe) -> String {
        format!(
            r#"
        window.setTimeout(() => {{
            const probe = document.querySelector('[data-evidence="sandbox-probe"]');
            if (!probe) {{
                throw new Error('Dioxus sandbox probe control is missing');
            }}
            probe.textContent = 'SANDBOX PROBE {name} ARMED';
            window.setTimeout(() => {{
                {action}
                window.setTimeout(() => {{
                    probe.textContent = 'SANDBOX PROBE {name} FIRED';
                }}, 0);
            }}, 10000);
        }}, 5000);
    "#,
            name = probe.name(),
            action = match probe {
                SandboxProbe::Anchor => format!(
                    "const anchor = document.createElement('a'); anchor.href = '{}'; document.body.append(anchor); anchor.click();",
                    probe.denial_url()
                ),
                SandboxProbe::Ipc => format!(
                    "window.ipc.postMessage(JSON.stringify({{ method: 'browser_open', params: {{ 'href': '{}' }} }}));",
                    probe.denial_url()
                ),
                SandboxProbe::Location =>
                    format!("window.location.assign('{}');", probe.denial_url()),
            },
        )
    }

    /// Starts the diagnostic interface with synthetic, non-production data.
    pub fn run() {
        if let Err(message) = sandbox_probe_from_env(
            std::env::var_os("TERSA_DIOXUS_EVIDENCE").as_deref(),
            std::env::var_os("TERSA_DIOXUS_SANDBOX_PROBE").as_deref(),
        ) {
            eprintln!("TERSA-DIOXUS-CONFIG-ERROR {message}");
            #[expect(
                clippy::exit,
                reason = "Invalid evidence configuration must fail before the event loop starts"
            )]
            std::process::exit(2);
        }
        let config = platform_config();
        dioxus_desktop::launch::launch(app, Vec::new(), vec![Box::new(config)]);
    }

    fn platform_config() -> Config {
        let head = format!(
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1, viewport-fit=cover\">\
             <meta name=\"color-scheme\" content=\"light\"><style>{STYLE}</style>"
        );
        let config = Config::new()
            .with_custom_index(INDEX.to_owned())
            .with_custom_head(head)
            .with_incognito(true)
            .with_navigation_handler(|url| {
                eprintln!("TERSA-DIOXUS-NAV-DENIED {url}");
                false
            })
            .with_disable_context_menu(true)
            .with_background_color((246, 244, 238, 255))
            .with_custom_event_handler(|event, _| match event {
                dioxus_desktop::tao::event::Event::Resumed => {
                    eprintln!("TERSA-DIOXUS-LIFECYCLE resumed");
                }
                dioxus_desktop::tao::event::Event::Suspended => {
                    eprintln!("TERSA-DIOXUS-LIFECYCLE suspended");
                }
                _ => {}
            });

        #[cfg(target_os = "macos")]
        let config = config.with_window(
            WindowBuilder::new()
                .with_title("tersa.app — Dioxus M0")
                .with_inner_size(LogicalSize::new(1_180.0, 780.0)),
        );

        config
    }

    #[component]
    fn app() -> Element {
        let mut scroll_top = use_signal(|| 0.0_f64);
        let mut draft = use_signal(String::new);
        let mut focus_state = use_signal(|| String::from("active — initial render"));
        let mut focus_events = use_signal(|| 0_u32);
        let mut safe_area_top = use_signal(|| -1_i32);
        let mut viewport_height = use_signal(|| ROW_HEIGHT_PX * 9.0);
        let sandbox_probe = sandbox_probe_from_env(
            std::env::var_os("TERSA_DIOXUS_EVIDENCE").as_deref(),
            std::env::var_os("TERSA_DIOXUS_SANDBOX_PROBE").as_deref(),
        )
        .expect("sandbox probe was validated before event-loop launch");

        use_effect(move || {
            spawn(async move {
                if let Err(error) = dioxus_document::eval(VIRTUALIZER_SCRIPT).await {
                    eprintln!("TERSA-DIOXUS-VIRTUALIZER error: {error}");
                }
            });
            if std::env::var_os("TERSA_DIOXUS_EVIDENCE").is_some() {
                let evidence_script = match sandbox_probe {
                    Some(probe) => sandbox_probe_script(probe),
                    None if std::env::var_os("TERSA_DIOXUS_RELAUNCH").is_some() => {
                        RELAUNCH_EVIDENCE_SCRIPT.to_owned()
                    }
                    None => EVIDENCE_SCRIPT.to_owned(),
                };
                spawn(async move {
                    if let Err(error) = dioxus_document::eval(&evidence_script).await {
                        eprintln!("TERSA-DIOXUS-EVIDENCE error: {error}");
                    }
                });
            }
        });

        let first_visible = visible_row_index(scroll_top());
        let start = first_visible.saturating_sub(OVERSCAN_ROWS);
        let visible_rows = visible_row_count(viewport_height())
            .min(MAX_RENDERED_ROWS.saturating_sub(OVERSCAN_ROWS.saturating_mul(2)));
        let end = (first_visible + visible_rows + OVERSCAN_ROWS).min(INBOX_ROWS);
        let rendered_rows = end.saturating_sub(start);
        let list_height = f64::from(u32::try_from(INBOX_ROWS).unwrap_or(u32::MAX)) * ROW_HEIGHT_PX;
        let protocol_version = tersa_presentation::presentation_protocol_version();
        let safe_area_top_label = if safe_area_top() < 0 {
            String::from("SAFE TOP PENDING")
        } else {
            format!("SAFE TOP {} PX", safe_area_top())
        };

        rsx! {
            main {
                class: "app-shell",
                tabindex: "-1",
                onfocusin: move |_| {
                    focus_state.set(String::from("active — WebView focus event"));
                    *focus_events.write() += 1;
                },
                onfocusout: move |_| {
                    focus_state.set(String::from("inactive — WebView blur event"));
                    *focus_events.write() += 1;
                },
                div {
                    class: "safe-area-probe",
                    aria_hidden: "true",
                    onmounted: move |event| async move {
                        if let Ok(rect) = event.data().get_client_rect().await {
                            #[expect(
                                clippy::cast_possible_truncation,
                                reason = "Apple safe-area insets are small integral display pixels"
                            )]
                            safe_area_top.set(rect.size.height.round() as i32);
                        }
                    }
                }
                header { class: "topbar",
                    div { class: "brand-lockup",
                        span { class: "brand-mark", aria_hidden: "true", "t" }
                        div {
                            strong { "tersa.app" }
                            span { "Dioxus WebView feasibility" }
                        }
                    }
                    div { class: "header-diagnostics",
                        span { class: "safe-area-status", role: "status", "{safe_area_top_label}" }
                        span { class: "transport-badge", "LOCAL SYNTHETIC DATA" }
                    }
                }
                div { class: "workspace",
                    nav { class: "sidebar", aria_label: "Diagnostic mailbox navigation",
                        p { class: "eyebrow", "M0 FALLBACK CANDIDATE" }
                        h1 { "Inbox" }
                        ul {
                            li { button { class: "nav-item selected", aria_current: "page", disabled: true, "Inbox", span { "10k" } } }
                            li { button { class: "nav-item", disabled: true, "Starred", span { "24" } } }
                            li { button { class: "nav-item", disabled: true, "Drafts", span { "3" } } }
                            li { button { class: "nav-item", disabled: true, "Sent" } }
                        }
                        section { class: "probe-card", aria_labelledby: "focus-title",
                            h2 { id: "focus-title", "WebView focus probe" }
                            output { aria_live: "polite", "{focus_state}" }
                            p { "Focus transitions: {focus_events}" }
                            p { "Safe area: CSS env insets enabled" }
                        }
                    }
                    section { class: "inbox-panel", aria_labelledby: "inbox-title",
                        div { class: "inbox-header",
                            div {
                                p { class: "eyebrow", "TERSA-DIOXUS-M0-THREAD" }
                                h2 { id: "inbox-title", "INBOX / 10,000 ROWS" }
                            }
                            label { class: "search-field",
                                span { "Search synthetic mail" }
                                input {
                                    r#type: "search",
                                    placeholder: "sender, subject, label",
                                    autocomplete: "off"
                                }
                            }
                        }
                        div { class: "virtual-diagnostics",
                            output { role: "status", aria_live: "polite",
                                "DOM ROWS {rendered_rows} / FIRST ROW {start} / END ROW {end}"
                            }
                            output {
                                "data-evidence": "actual-dom-rows",
                                "ACTUAL DOM ROWS PENDING"
                            }
                            output {
                                "data-evidence": "navigation",
                                "NAVIGATION PROBE PENDING"
                            }
                            output {
                                "data-evidence": "storage",
                                "STORAGE PROBE PENDING"
                            }
                            output {
                                "data-evidence": "cookie",
                                "COOKIE PROBE PENDING"
                            }
                            output {
                                "data-evidence": "popup",
                                "WINDOW OPEN PROBE PENDING"
                            }
                            output {
                                "data-evidence": "sandbox-probe",
                                "SANDBOX PROBE PENDING"
                            }
                            button {
                                r#type: "button",
                                "data-evidence": "advance-list",
                                onclick: move |_| {
                                    spawn(async move {
                                        if let Err(error) = dioxus_document::eval(JUMP_SCRIPT).await {
                                            eprintln!("TERSA-DIOXUS-JUMP error: {error}");
                                        }
                                    });
                                },
                                "Jump to row 100"
                            }
                        }
                        div {
                            class: "virtual-list",
                            "data-evidence": "virtual-list",
                            "data-expected-rows": "{rendered_rows}",
                            onscroll: move |event| {
                                scroll_top.set(event.data().scroll_top().max(0.0));
                                viewport_height.set(f64::from(event.data().client_height().max(1)));
                            },
                            div {
                                class: "virtual-spacer",
                                role: "list",
                                aria_label: "Synthetic inbox",
                                style: "height: {list_height}px",
                                for index in start..end {
                                    MailRow { key: "{index}", index }
                                }
                            }
                        }
                    }
                    aside { class: "composer", aria_labelledby: "composer-title",
                        p { class: "eyebrow", "INPUT AND IME PROBE" }
                        h2 { id: "composer-title", "Draft reply" }
                        label {
                            span { "Message" }
                            textarea {
                                rows: "10",
                                placeholder: "Type, dictate, select, and edit here…",
                                autocapitalize: "sentences",
                                autocomplete: "on",
                                spellcheck: "true",
                                "data-evidence": "composer",
                                value: "{draft}",
                                oninput: move |event| draft.set(event.value())
                            }
                        }
                        output { class: "draft-status", aria_live: "polite",
                            "{draft().chars().count()} characters — not explicitly saved"
                        }
                        div { class: "composer-actions",
                            button { class: "secondary", disabled: true, "Discard" }
                            button { class: "primary", disabled: true, "Save synthetic draft" }
                        }
                        dl { class: "runtime-facts",
                            div { dt { "Runtime" } dd { "Dioxus 0.7.9 / WKWebView" } }
                            div { dt { "Transport" } dd { "Authenticated loopback only" } }
                            div { dt { "Lifecycle" } dd { "Tao log markers" } }
                            div { dt { "Protocol" } dd { "presentation v{protocol_version}" } }
                        }
                    }
                }
            }
        }
    }

    #[component]
    fn MailRow(index: usize) -> Element {
        let class = if index % 4 == 0 {
            "mail-row unread"
        } else {
            "mail-row"
        };
        let sender = format!("Research desk {:03}", index % 250);
        let subject = format!("Diagnostic thread {:05}", index + 1);
        let time = format!("{:02}:{:02}", 8 + index % 10, index % 60);
        let row_offset = f64::from(u32::try_from(index).unwrap_or(u32::MAX)) * ROW_HEIGHT_PX;
        let position = index + 1;

        rsx! {
            article {
                class,
                role: "listitem",
                tabindex: "0",
                aria_label: "{sender}, {subject}, synthetic message {position}",
                aria_setsize: "{INBOX_ROWS}",
                aria_posinset: "{position}",
                style: "transform: translateY({row_offset}px)",
                div { class: "sender", "{sender}" }
                div { class: "message-copy",
                    strong { "{subject}" }
                    span { "Synthetic row for scroll, focus, and accessibility evidence." }
                }
                time { "{time}" }
            }
        }
    }

    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "The non-negative bounded scroll offset is intentionally converted to a row index"
    )]
    fn visible_row_index(scroll_top: f64) -> usize {
        (scroll_top.max(0.0) / ROW_HEIGHT_PX).floor() as usize
    }

    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "The positive viewport height is intentionally converted to a bounded row count"
    )]
    fn visible_row_count(viewport_height: f64) -> usize {
        (viewport_height.max(ROW_HEIGHT_PX) / ROW_HEIGHT_PX).ceil() as usize
    }

    #[cfg(test)]
    mod tests {
        use super::{
            MAX_RENDERED_ROWS, OVERSCAN_ROWS, ROW_HEIGHT_PX, SandboxProbe, sandbox_probe_from_env,
            visible_row_count,
        };

        #[test]
        fn visible_rows_cover_the_complete_viewport() {
            assert_eq!(visible_row_count(ROW_HEIGHT_PX * 9.0), 9);
            assert_eq!(visible_row_count(ROW_HEIGHT_PX * 9.5), 10);
        }

        #[test]
        fn visible_rows_never_become_empty() {
            assert_eq!(visible_row_count(0.0), 1);
        }

        #[test]
        fn rendered_row_budget_can_never_exceed_the_evidence_limit() {
            let visible_rows = visible_row_count(ROW_HEIGHT_PX * 10_000.0)
                .min(MAX_RENDERED_ROWS.saturating_sub(OVERSCAN_ROWS.saturating_mul(2)));

            assert_eq!(visible_rows + (OVERSCAN_ROWS * 2), MAX_RENDERED_ROWS);
        }

        #[test]
        fn sandbox_probe_mapping_requires_evidence_and_exact_values() {
            assert_eq!(sandbox_probe_from_env(None, None), Ok(None));
            assert_eq!(
                sandbox_probe_from_env(None, Some("anchor".as_ref())),
                Err("TERSA_DIOXUS_SANDBOX_PROBE requires TERSA_DIOXUS_EVIDENCE")
            );
            assert_eq!(
                sandbox_probe_from_env(Some("1".as_ref()), Some("anchor".as_ref())),
                Ok(Some(SandboxProbe::Anchor))
            );
            assert_eq!(
                sandbox_probe_from_env(Some("1".as_ref()), Some("ipc".as_ref())),
                Ok(Some(SandboxProbe::Ipc))
            );
            assert_eq!(
                sandbox_probe_from_env(Some("1".as_ref()), Some("location".as_ref())),
                Ok(Some(SandboxProbe::Location))
            );
            assert_eq!(
                sandbox_probe_from_env(Some("1".as_ref()), Some("ANCHOR".as_ref())),
                Err("TERSA_DIOXUS_SANDBOX_PROBE must be anchor, ipc, or location")
            );
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn main() {
    apple::run();
}

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
fn main() {
    // The diagnostic executable is intentionally Apple-target-only.
    let _ = tersa_presentation::presentation_protocol_version();
}

// Rust guideline compliant 1.0.
