import streamlit as st
from cyberguard_engine import analyze_message_and_urls


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="CyberGuard",
    page_icon="🛡️",
    layout="wide"
)


# ============================================================
# HEADER
# ============================================================

st.title("🛡️ CyberGuard")

st.subheader(
    "AI-Powered Cyber Threat, Phishing & "
    "Digital Impersonation Detection"
)

st.write(
    "Analyze emails, SMS, social-media messages, "
    "and suspicious URLs for potential phishing threats."
)

st.divider()


# ============================================================
# INPUT
# ============================================================

message = st.text_area(
    "📩 Enter a message to analyze",
    placeholder=(
        "Paste an email, SMS, social-media message, "
        "or suspicious message here..."
    ),
    height=180
)


# ============================================================
# SCAN BUTTON
# ============================================================

if st.button(
    "🔍 Scan with CyberGuard",
    type="primary",
    use_container_width=True
):

    if not message.strip():

        st.warning(
            "Please enter a message before scanning."
        )

    else:

        with st.spinner(
            "CyberGuard is analyzing the message..."
        ):

            try:

                result = analyze_message_and_urls(
                    message
                )

                message_report = result[
                    "message_report"
                ]

                url_reports = result[
                    "url_reports"
                ]

                # ====================================================
                # MESSAGE REPORT
                # ====================================================

                st.divider()

                st.header(
                    "🛡️ CyberGuard Threat Report"
                )

                col1, col2, col3 = st.columns(3)

                with col1:
                    st.metric(
                        "Status",
                        message_report["status"]
                    )

                with col2:
                    st.metric(
                        "Risk Level",
                        message_report["risk_level"]
                    )

                with col3:
                    st.metric(
                        "Risk Score",
                        f'{message_report["risk_score"]} / 100'
                    )

                # ====================================================
                # DETECTED INDICATORS
                # ====================================================

                st.subheader(
                    "⚠️ Detected Threat Indicators"
                )

                categories = message_report[
                    "detected_categories"
                ]

                if categories:

                    for category, indicators in categories.items():

                        st.markdown(
                            f"### ⚠️ {category}"
                        )

                        for indicator in indicators:

                            st.write(
                                f"• `{indicator}`"
                            )

                else:

                    st.success(
                        "No suspicious message indicators detected."
                    )

                # ====================================================
                # URL ANALYSIS
                # ====================================================

                if url_reports:

                    st.divider()

                    st.header(
                        "🔗 URL Analysis"
                    )

                    for url_report in url_reports:

                        st.code(
                            url_report["url"],
                            language=None
                        )

                        url_col1, url_col2, url_col3 = st.columns(3)

                        with url_col1:

                            st.metric(
                                "Status",
                                url_report["status"]
                            )

                        with url_col2:

                            st.metric(
                                "Risk Level",
                                url_report["risk_level"]
                            )

                        with url_col3:

                            st.metric(
                                "Risk Score",
                                f'{url_report["risk_score"]} / 100'
                            )

                        brands = url_report[
                            "possible_impersonated_brands"
                        ]

                        if brands:

                            st.warning(
                                "Possible Brand Impersonation: "
                                + ", ".join(brands)
                            )

                        indicators = url_report[
                            "detected_indicators"
                        ]

                        if indicators:

                            st.markdown(
                                "**Detected URL Indicators:**"
                            )

                            for indicator in indicators:

                                st.write(
                                    f"• {indicator}"
                                )

                        st.info(
                            url_report[
                                "recommendation"
                            ]
                        )

                # ====================================================
                # RECOMMENDATION
                # ====================================================

                st.divider()

                st.subheader(
                    "💡 Recommendation"
                )

                st.info(
                    message_report[
                        "recommendation"
                    ]
                )

            except Exception as e:

                st.error(
                    "An error occurred during analysis."
                )

                st.exception(e)


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "CyberGuard Prototype — AI-assisted cyber threat detection. "
    "Risk scores are decision-support signals and are not "
    "guaranteed proof of malicious activity."
)
