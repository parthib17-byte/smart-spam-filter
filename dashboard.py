import streamlit as st
import requests
import pandas as pd

# =========================================================
# CONFIG
# =========================================================

API_URL = "http://localhost:8000"

st.set_page_config(
    page_title="Smart Spam Filter",
    page_icon="🛡️",
    layout="wide"
)

# =========================================================
# SESSION STATE
# =========================================================

if "session_id" not in st.session_state:
    st.session_state["session_id"] = None

if "email" not in st.session_state:
    st.session_state["email"] = None

if "name" not in st.session_state:
    st.session_state["name"] = None

if "scan_data" not in st.session_state:
    st.session_state["scan_data"] = None


# =========================================================
# GOOGLE OAUTH CALLBACK
# =========================================================

auth_code = st.query_params.get("auth_code")

if auth_code and not st.session_state["session_id"]:

    try:
        response = requests.get(
            f"{API_URL}/auth/exchange",
            params={"code": auth_code},
            timeout=20
        )

        if response.status_code == 200:

            data = response.json()

            if data.get("success"):

                st.session_state["session_id"] = data.get(
                    "session_id"
                )

                st.session_state["email"] = data.get(
                    "email"
                )

                st.session_state["name"] = data.get(
                    "name"
                )

                # Remove auth_code from browser URL
                st.query_params.clear()

                st.rerun()

            else:
                st.error(
                    "❌ Login code is invalid or expired."
                )

        else:
            st.error(
                f"❌ Authentication failed: "
                f"{response.status_code}"
            )

    except requests.exceptions.ConnectionError:

        st.error(
            "❌ FastAPI server is not running.\n\n"
            "Please start FastAPI first."
        )

    except requests.exceptions.Timeout:

        st.error(
            "⏱️ Authentication request timed out."
        )

    except Exception as e:

        st.error(
            f"❌ Authentication error: {str(e)}"
        )


# =========================================================
# HEADER
# =========================================================

st.title("🛡️ Smart Spam Filter")

st.caption(
    "AI-powered Gmail Spam Detection & Automation"
)

st.divider()


# =========================================================
# LOGIN PAGE
# =========================================================

if not st.session_state["session_id"]:

    st.info(
        "🔐 Connect your Gmail account to start "
        "detecting and cleaning spam emails."
    )

    st.write("### 🚀 Get Started")

    login_url = f"{API_URL}/auth/login"

    st.link_button(
        "🔐 Sign in with Google",
        login_url,
        use_container_width=True
    )

    st.divider()

    col1, col2, col3 = st.columns(3)

    with col1:
        st.success(
            "🤖 AI Detection\n\n"
            "TF-IDF + Logistic Regression"
        )

    with col2:
        st.info(
            "📧 Gmail Integration\n\n"
            "Secure Gmail API access"
        )

    with col3:
        st.warning(
            "🛡️ Smart Protection\n\n"
            "Spam classification & cleanup"
        )

    st.divider()

    st.caption(
        "Smart Spam Filter | FastAPI + Gmail API + "
        "TF-IDF + Logistic Regression + Streamlit"
    )

    st.stop()


# =========================================================
# LOGGED-IN USER
# =========================================================

st.success(
    f"👋 Welcome, {st.session_state['name'] or 'User'}!"
)

col1, col2 = st.columns([4, 1])

with col1:

    st.write(
        f"📧 **Connected Gmail:** "
        f"`{st.session_state['email']}`"
    )

with col2:

    if st.button(
        "🚪 Logout",
        use_container_width=True
    ):

        try:

            requests.post(
                f"{API_URL}/auth/logout",
                params={
                    "session_id": st.session_state[
                        "session_id"
                    ]
                },
                timeout=10
            )

        except Exception:
            pass

        st.session_state["session_id"] = None
        st.session_state["email"] = None
        st.session_state["name"] = None
        st.session_state["scan_data"] = None

        st.rerun()


st.divider()


# =========================================================
# GMAIL SCANNER
# =========================================================

st.subheader("📧 Gmail Scanner")

if st.button(
    "🔄 Scan Gmail Now",
    use_container_width=True
):

    try:

        with st.spinner(
            "🔍 Scanning your Gmail with AI..."
        ):

            response = requests.get(
                f"{API_URL}/scan",
                params={
                    "session_id": st.session_state[
                        "session_id"
                    ]
                },
                timeout=120
            )

        # -------------------------------------------------
        # SUCCESS
        # -------------------------------------------------

        if response.status_code == 200:

            data = response.json()

            if "error" in data:

                st.error(
                    f"❌ {data['error']}"
                )

            else:

                st.session_state["scan_data"] = data

                st.success(
                    "✅ Gmail scan completed successfully!"
                )

        # -------------------------------------------------
        # SESSION EXPIRED
        # -------------------------------------------------

        elif response.status_code == 401:

            st.error(
                "🔐 Your session has expired. "
                "Please login again."
            )

            st.session_state["session_id"] = None
            st.session_state["email"] = None
            st.session_state["name"] = None
            st.session_state["scan_data"] = None

        # -------------------------------------------------
        # OTHER ERROR
        # -------------------------------------------------

        else:

            st.error(
                f"❌ FastAPI Error: "
                f"{response.status_code}"
            )

    except requests.exceptions.ConnectionError:

        st.error(
            "❌ FastAPI server is not running.\n\n"
            "Please start FastAPI first."
        )

    except requests.exceptions.Timeout:

        st.error(
            "⏱️ Gmail scan timed out."
        )

    except Exception as e:

        st.error(
            f"❌ Error: {str(e)}"
        )


# =========================================================
# SCAN RESULTS
# =========================================================

data = st.session_state.get("scan_data")


if data:

    total = data.get(
        "count",
        0
    )

    new_count = data.get(
        "new_count",
        0
    )

    spam_count = data.get(
        "spam_count",
        0
    )

    ham_count = data.get(
        "ham_count",
        0
    )

    trash_count = data.get(
        "trash_count",
        0
    )

    labelled_count = data.get(
        "labelled_count",
        0
    )

    skipped_count = data.get(
        "skipped_count",
        0
    )

    spam_percentage = (
        (spam_count / new_count) * 100
        if new_count > 0
        else 0
    )


    # =====================================================
    # STATISTICS
    # =====================================================

    st.divider()

    st.subheader("📊 Scan Statistics")

    col1, col2, col3, col4 = st.columns(4)

    col1.metric(
        "📧 Emails Checked",
        total
    )

    col2.metric(
        "🆕 New Emails",
        new_count
    )

    col3.metric(
        "🚨 Spam",
        spam_count
    )

    col4.metric(
        "✅ Ham",
        ham_count
    )


    col5, col6, col7, col8 = st.columns(4)

    col5.metric(
        "🗑️ Trashed",
        trash_count
    )

    col6.metric(
        "🏷️ AI-SPAM",
        labelled_count
    )

    col7.metric(
        "⏭️ Skipped",
        skipped_count
    )

    col8.metric(
        "📈 Spam %",
        f"{spam_percentage:.1f}%"
    )


    # =====================================================
    # AI CONFIGURATION
    # =====================================================

    st.divider()

    st.subheader("🎯 AI Configuration")

    col1, col2 = st.columns(2)

    with col1:

        st.info(
            f"🏷️ **AI-SPAM Threshold:** "
            f"{data.get('spam_threshold', 0.31)}"
        )

    with col2:

        st.warning(
            f"🗑️ **Trash Threshold:** "
            f"{data.get('trash_threshold', 0.80)}"
        )


    # =====================================================
    # EMAIL RESULTS
    # =====================================================

    st.divider()

    st.subheader("📋 Email Results")

    emails = data.get(
        "emails",
        []
    )

    if emails:

        rows = []

        for email in emails:

            rows.append(
                {
                    "From": email.get(
                        "from",
                        ""
                    ),

                    "Subject": email.get(
                        "subject",
                        ""
                    ),

                    "Prediction": email.get(
                        "prediction",
                        ""
                    ),

                    "Spam Probability": email.get(
                        "spam_probability",
                        0
                    ),

                    "Confidence": email.get(
                        "confidence",
                        0
                    ),

                    "Action": email.get(
                        "action",
                        ""
                    )
                }
            )

        df = pd.DataFrame(rows)

        if not df.empty:

            df["Spam Probability"] = (
                pd.to_numeric(
                    df["Spam Probability"],
                    errors="coerce"
                )
                .fillna(0)
                .mul(100)
                .round(2)
                .astype(str)
                + "%"
            )

            df["Confidence"] = (
                pd.to_numeric(
                    df["Confidence"],
                    errors="coerce"
                )
                .fillna(0)
                .mul(100)
                .round(2)
                .astype(str)
                + "%"
            )

            st.dataframe(
                df,
                use_container_width=True,
                hide_index=True
            )

    else:

        st.info(
            "📭 No new emails were processed "
            "in this scan."
        )


else:

    st.info(
        "👆 Click **Scan Gmail Now** "
        "to start scanning your Gmail."
    )


# =========================================================
# SYSTEM INFORMATION
# =========================================================

st.divider()

st.subheader("⚙️ System Information")

col1, col2, col3 = st.columns(3)

with col1:

    st.success(
        "🤖 ML Model\n\n"
        "TF-IDF + Logistic Regression"
    )

with col2:

    st.info(
        "🚀 Backend\n\n"
        "FastAPI + Gmail API"
    )

with col3:

    st.warning(
        "🖥️ Frontend\n\n"
        "Streamlit Dashboard"
    )


st.divider()

st.caption(
    "Smart Spam Filter | FastAPI + Gmail API + "
    "TF-IDF + Logistic Regression + Streamlit"
)