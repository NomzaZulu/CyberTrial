import streamlit as st
from cyberphishing_engine import (
    analyze_message_and_urls,
    scan_qr_file
)

st.set_page_config(
    page_title="CyberGuard",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ CyberGuard")
st.subheader(
    "AI-Powered Cyber Threat, Phishing & "
    "Digital Impersonation Detection"
)

st.write(
    "Analyze emails, SMS, social-media messages, "
    "suspicious URLs, and QR codes for potential phishing threats."
)

st.divider()


# ============================================================
# MESSAGE / URL ANALYSIS
# ============================================================

st.header("📩 Message & URL Scanner")

message = st.text_area(
    "Enter a message to analyze",
    placeholder=(
        "Paste an email, SMS, social-media message, "
        "or suspicious message here..."
    ),
    height=180
)

if st.button(
    "🔍 Scan Message",
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

                result = analyze_message_and_urls(message)

                message_report = result["message_report"]
                url_reports = result["url_reports"]

                st.divider()
                st.header("🛡️ CyberGuard Threat Report")

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

                # --------------------------------------------
                # MESSAGE INDICATORS
                # --------------------------------------------

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

                # --------------------------------------------
                # URL ANALYSIS
                # --------------------------------------------

                if url_reports:

                    st.divider()
                    st.header("🔗 URL Analysis")

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
                            url_report["recommendation"]
                        )

                # --------------------------------------------
                # RECOMMENDATION
                # --------------------------------------------

                st.divider()

                st.subheader("💡 Recommendation")

                st.info(
                    message_report["recommendation"]
                )

            except Exception as e:

                st.error(
                    "An error occurred during analysis."
                )

                st.exception(e)


# ============================================================
# QR CODE ANALYSIS
# ============================================================

st.divider()

st.header("📷 QR Code Scanner")

st.write(
    "Upload a QR code image. CyberGuard will decode the QR "
    "payload and analyze it for potential phishing threats."
)

qr_file = st.file_uploader(
    "Upload QR Code Image",
    type=["png", "jpg", "jpeg"]
)

if qr_file is not None:

    st.image(
        qr_file,
        caption="Uploaded QR Code",
        width=250
    )

    if st.button(
        "🔍 Scan QR Code",
        type="primary",
        use_container_width=True
    ):

        try:

            # Save uploaded file temporarily
            temp_filename = "uploaded_qr.png"

            with open(temp_filename, "wb") as f:

                f.write(qr_file.getbuffer())

            with st.spinner(
                "CyberGuard is decoding and analyzing the QR code..."
            ):

                result = scan_qr_file(
                    temp_filename
                )

            # --------------------------------------------
            # NO QR DETECTED
            # --------------------------------------------

            if result["payload"] is None:

                st.error(
                    "No QR code could be detected in the image."
                )

            else:

                analysis = result["analysis"]

                st.divider()

                st.header(
                    "🛡️ QR Threat Report"
                )

                # ----------------------------------------
                # QR PAYLOAD
                # ----------------------------------------

                st.subheader(
                    "📦 Decoded QR Payload"
                )

                st.code(
                    result["payload"],
                    language=None
                )

                st.metric(
                    "Payload Type",
                    result["payload_type"]
                )

                # ----------------------------------------
                # ANALYSIS
                # ----------------------------------------

                st.subheader(
                    "🔍 Analysis"
                )

                if result["payload_type"] == "URL":

                    col1, col2, col3 = st.columns(3)

                    with col1:

                        st.metric(
                            "Status",
                            analysis["status"]
                        )

                    with col2:

                        st.metric(
                            "Risk Level",
                            analysis["risk_level"]
                        )

                    with col3:

                        st.metric(
                            "Risk Score",
                            f'{analysis["risk_score"]} / 100'
                        )

                    brands = analysis[
                        "possible_impersonated_brands"
                    ]

                    if brands:

                        st.warning(
                            "Possible Brand Impersonation: "
                            + ", ".join(brands)
                        )

                    indicators = analysis[
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
                        analysis["recommendation"]
                    )

                else:

                    col1, col2, col3 = st.columns(3)

                    with col1:

                        st.metric(
                            "Status",
                            analysis["status"]
                        )

                    with col2:

                        st.metric(
                            "Risk Level",
                            analysis["risk_level"]
                        )

                    with col3:

                        st.metric(
                            "Risk Score",
                            f'{analysis["risk_score"]} / 100'
                        )

                    categories = analysis[
                        "detected_categories"
                    ]

                    if categories:

                        st.markdown(
                            "**Detected Threat Indicators:**"
                        )

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

                    st.info(
                        analysis["recommendation"]
                    )

        except Exception as e:

            st.error(
                "An error occurred while scanning the QR code."
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
