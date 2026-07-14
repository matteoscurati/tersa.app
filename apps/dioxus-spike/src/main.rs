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
    const VISIBLE_ROWS: usize = 9;
    const OVERSCAN_ROWS: usize = 6;
    const STYLE: &str = include_str!("style.css");
    const EVIDENCE_SCRIPT: &str = r#"
        window.setTimeout(() => {
            const list = document.querySelector('[data-evidence="virtual-list"]');
            const editor = document.querySelector('[data-evidence="composer"]');
            if (!list || !editor) {
                throw new Error('Dioxus evidence controls are missing');
            }
            list.scrollTop = 7600;
            list.dispatchEvent(new Event('scroll', { bubbles: true }));

            const setter = Object.getOwnPropertyDescriptor(
                HTMLTextAreaElement.prototype,
                'value'
            ).set;
            setter.call(
                editor,
                'TERSA DIOXUS INPUT ONE\nTERSA DIOXUS INPUT TWO'
            );
            editor.dispatchEvent(new Event('input', { bubbles: true }));
            editor.focus();
        }, 5000);
    "#;

    /// Starts the diagnostic interface with synthetic, non-production data.
    pub fn run() {
        let config = platform_config();
        dioxus_desktop::launch::launch(app, Vec::new(), vec![Box::new(config)]);
    }

    fn platform_config() -> Config {
        let head = format!(
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1, viewport-fit=cover\">\
             <meta name=\"color-scheme\" content=\"light\"><style>{STYLE}</style>"
        );
        let config = Config::new()
            .with_custom_head(head)
            .with_navigation_handler(|_| false)
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

        use_effect(|| {
            if std::env::var_os("TERSA_DIOXUS_EVIDENCE").is_some() {
                spawn(async move {
                    if let Err(error) = dioxus_document::eval(EVIDENCE_SCRIPT).await {
                        eprintln!("TERSA-DIOXUS-EVIDENCE error: {error}");
                    }
                });
            }
        });

        let first_visible = visible_row_index(scroll_top());
        let start = first_visible.saturating_sub(OVERSCAN_ROWS);
        let end = (first_visible + VISIBLE_ROWS + OVERSCAN_ROWS).min(INBOX_ROWS);
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
                onfocus: move |_| {
                    focus_state.set(String::from("active — WebView focus event"));
                    *focus_events.write() += 1;
                },
                onblur: move |_| {
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
                            li { button { class: "nav-item selected", aria_current: "page", "Inbox", span { "10k" } } }
                            li { button { class: "nav-item", "Starred", span { "24" } } }
                            li { button { class: "nav-item", "Drafts", span { "3" } } }
                            li { button { class: "nav-item", "Sent" } }
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
                        div { class: "virtual-diagnostics", role: "status", aria_live: "polite",
                            "DOM ROWS {rendered_rows} / FIRST ROW {start} / END ROW {end}"
                        }
                        div {
                            class: "virtual-list",
                            role: "list",
                            aria_label: "Synthetic inbox",
                            "data-evidence": "virtual-list",
                            onscroll: move |event| scroll_top.set(event.data().scroll_top().max(0.0)),
                            div {
                                class: "virtual-spacer",
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
                            "{draft().chars().count()} characters — never persisted"
                        }
                        div { class: "composer-actions",
                            button { class: "secondary", "Discard" }
                            button { class: "primary", "Save synthetic draft" }
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
