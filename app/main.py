import os
import json
import secrets
from datetime import datetime, timezone

import joblib
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from starlette.middleware.sessions import SessionMiddleware
from authlib.integrations.starlette_client import OAuth

from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials


# =========================================================
# PATHS
# =========================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

MODEL_PATH = os.path.join(
    BASE_DIR,
    "models",
    "spam_classifier.pkl"
)

VECTORIZER_PATH = os.path.join(
    BASE_DIR,
    "models",
    "tfidf_vectorizer.pkl"
)


# =========================================================
# ENVIRONMENT VARIABLES
# =========================================================

BACKEND_URL = os.getenv(
    "BACKEND_URL",
    "http://localhost:8000"
).rstrip("/")

DASHBOARD_URL = os.getenv(
    "DASHBOARD_URL",
    "http://localhost:8501"
).rstrip("/")

SESSION_SECRET = os.getenv(
    "SESSION_SECRET",
    "local-development-secret-change-this"
)

GOOGLE_CLIENT_ID = os.getenv(
    "GOOGLE_CLIENT_ID"
)

GOOGLE_CLIENT_SECRET = os.getenv(
    "GOOGLE_CLIENT_SECRET"
)


# =========================================================
# GOOGLE OAUTH CONFIG
# =========================================================

GOOGLE_REDIRECT_URI = (
    f"{BACKEND_URL}/auth/callback"
)

GOOGLE_DISCOVERY_URL = (
    "https://accounts.google.com/.well-known/openid-configuration"
)

GOOGLE_SCOPES = (
    "openid email profile "
    "https://www.googleapis.com/auth/gmail.modify"
)


# =========================================================
# APP
# =========================================================

app = FastAPI(
    title="Smart Spam Filter API",
    version="5.0.0"
)

app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    same_site="lax",
    https_only=BACKEND_URL.startswith("https://")
)


# =========================================================
# MODEL
# =========================================================

try:
    model = joblib.load(MODEL_PATH)
    tfidf = joblib.load(VECTORIZER_PATH)

    print("✅ ML model loaded successfully")

except Exception as e:
    print(f"❌ Failed to load ML model: {e}")
    model = None
    tfidf = None


# =========================================================
# THRESHOLDS
# =========================================================

SPAM_THRESHOLD = 0.31

# Only very high confidence spam goes to Trash.
TRASH_THRESHOLD = 0.80

SPAM_LABEL = "AI-SPAM"


# =========================================================
# IN-MEMORY USER SESSIONS
# =========================================================

USER_SESSIONS = {}

LOGIN_CODES = {}


# =========================================================
# OAUTH
# =========================================================

oauth = OAuth()

if GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET:

    oauth.register(
        name="google",

        client_id=GOOGLE_CLIENT_ID,

        client_secret=GOOGLE_CLIENT_SECRET,

        server_metadata_url=GOOGLE_DISCOVERY_URL,

        client_kwargs={
            "scope": GOOGLE_SCOPES
        }
    )

    print("✅ Google OAuth configured from environment variables")

else:

    # Local development fallback.
    #
    # Render should use environment variables instead of
    # credentials.json.

    credentials_path = os.path.join(
        BASE_DIR,
        "credentials.json"
    )

    if os.path.exists(credentials_path):

        try:

            with open(
                credentials_path,
                "r",
                encoding="utf-8"
            ) as f:

                credentials_data = json.load(f)

            web_config = credentials_data.get(
                "web",
                {}
            )

            local_client_id = web_config.get(
                "client_id"
            )

            local_client_secret = web_config.get(
                "client_secret"
            )

            if local_client_id and local_client_secret:

                oauth.register(
                    name="google",

                    client_id=local_client_id,

                    client_secret=local_client_secret,

                    server_metadata_url=GOOGLE_DISCOVERY_URL,

                    client_kwargs={
                        "scope": GOOGLE_SCOPES
                    }
                )

                print(
                    "✅ Google OAuth configured "
                    "from local credentials.json"
                )

            else:

                print(
                    "⚠️ credentials.json found, "
                    "but client_id/client_secret missing"
                )

        except Exception as e:

            print(
                f"❌ Failed to load credentials.json: {e}"
            )

    else:

        print(
            "⚠️ Google OAuth is not configured yet."
        )


# =========================================================
# HELPERS
# =========================================================

def get_google_client():
    """
    Return configured Google OAuth client.
    """

    try:

        return oauth.google

    except Exception:

        raise HTTPException(
            status_code=500,
            detail=(
                "Google OAuth is not configured. "
                "Set GOOGLE_CLIENT_ID and "
                "GOOGLE_CLIENT_SECRET."
            )
        )


def get_session(session_id: str):

    if not session_id:

        raise HTTPException(
            status_code=401,
            detail="Missing session_id"
        )

    session = USER_SESSIONS.get(
        session_id
    )

    if not session:

        raise HTTPException(
            status_code=401,
            detail="Invalid or expired session"
        )

    return session


def get_gmail_service(session):

    token = session.get("token")

    if not token:

        raise HTTPException(
            status_code=401,
            detail="Google authentication token missing"
        )

    try:

        credentials = Credentials(
            token=token.get("access_token"),
            refresh_token=token.get("refresh_token"),
            token_uri=token.get(
                "token_uri",
                "https://oauth2.googleapis.com/token"
            ),
            client_id=token.get(
                "client_id",
                GOOGLE_CLIENT_ID
            ),
            client_secret=token.get(
                "client_secret",
                GOOGLE_CLIENT_SECRET
            ),
            scopes=token.get(
                "scope"
            )
        )

        service = build(
            "gmail",
            "v1",
            credentials=credentials,
            cache_discovery=False
        )

        return service

    except Exception as e:

        print(
            f"❌ Gmail service error: {e}"
        )

        raise HTTPException(
            status_code=500,
            detail="Could not connect to Gmail"
        )


def decode_base64url(data):

    import base64

    if not data:
        return ""

    try:

        padding = "=" * (
            4 - len(data) % 4
        )

        decoded = base64.urlsafe_b64decode(
            data + padding
        )

        return decoded.decode(
            "utf-8",
            errors="ignore"
        )

    except Exception:

        return ""


def extract_email_body(payload):

    """
    Extract plain text from Gmail message payload.
    """

    if not payload:
        return ""

    mime_type = payload.get(
        "mimeType",
        ""
    )

    body = payload.get(
        "body",
        {}
    )

    data = body.get(
        "data"
    )

    if data and (
        mime_type == "text/plain"
        or not payload.get("parts")
    ):

        return decode_base64url(data)

    parts = payload.get(
        "parts",
        []
    )

    texts = []

    for part in parts:

        part_text = extract_email_body(
            part
        )

        if part_text:

            texts.append(
                part_text
            )

    return "\n".join(texts)


def get_header(headers, name):

    name = name.lower()

    for header in headers or []:

        if header.get(
            "name",
            ""
        ).lower() == name:

            return header.get(
                "value",
                ""
            )

    return ""


def predict_spam(subject, body):

    if model is None or tfidf is None:

        raise HTTPException(
            status_code=500,
            detail="ML model is not loaded"
        )

    text = (
        f"{subject} {body}"
    ).strip()

    features = tfidf.transform(
        [text]
    )

    probabilities = model.predict_proba(
        features
    )[0]

    spam_probability = float(
        probabilities[1]
    )

    if spam_probability >= SPAM_THRESHOLD:

        label = "SPAM"

    else:

        label = "HAM"

    return label, spam_probability


# =========================================================
# ROOT
# =========================================================

@app.get("/")
def root():

    return {
        "message": "Smart Spam Filter is running!",
        "version": "5.0.0",
        "authentication": "Google OAuth",
        "multi_user": True,
        "spam_threshold": SPAM_THRESHOLD,
        "trash_threshold": TRASH_THRESHOLD,
        "gmail_scope": "gmail.modify"
    }


# =========================================================
# HEALTH
# =========================================================

@app.get("/health")
def health():

    return {
        "status": "ok",
        "model_loaded": (
            model is not None
            and tfidf is not None
        ),
        "oauth_configured": (
            bool(
                GOOGLE_CLIENT_ID
                and GOOGLE_CLIENT_SECRET
            )
            or os.path.exists(
                os.path.join(
                    BASE_DIR,
                    "credentials.json"
                )
            )
        )
    }


# =========================================================
# GOOGLE LOGIN
# =========================================================

@app.get("/auth/login")
async def google_login(request: Request):

    google = get_google_client()

    redirect_uri = GOOGLE_REDIRECT_URI

    return await google.authorize_redirect(
        request,
        redirect_uri
    )


# =========================================================
# GOOGLE CALLBACK
# =========================================================

@app.get("/auth/callback")
async def google_callback(
    request: Request
):

    google = get_google_client()

    try:

        token = await google.authorize_access_token(
            request
        )

    except Exception as e:

        print(
            f"❌ OAuth callback error: {e}"
        )

        raise HTTPException(
            status_code=400,
            detail=f"Google authentication failed: {str(e)}"
        )

    # -----------------------------------------------------
    # Get Google user information
    # -----------------------------------------------------

    userinfo = token.get(
        "userinfo"
    )

    if not userinfo:

        try:

            userinfo_response = await google.get(
                "https://openidconnect.googleapis.com/v1/userinfo",
                token=token
            )

            userinfo = userinfo_response.json()

        except Exception as e:

            print(
                f"❌ Failed to get user info: {e}"
            )

            raise HTTPException(
                status_code=400,
                detail="Could not retrieve Google user information"
            )

    email = userinfo.get(
        "email"
    )

    name = userinfo.get(
        "name",
        "Gmail User"
    )

    if not email:

        raise HTTPException(
            status_code=400,
            detail="Google account email not found"
        )

    # -----------------------------------------------------
    # Create opaque session ID
    # -----------------------------------------------------

    session_id = secrets.token_urlsafe(
        32
    )

    USER_SESSIONS[session_id] = {

        "email": email,

        "name": name,

        "token": token,

        "created_at": datetime.now(
            timezone.utc
        ).isoformat()
    }

    # -----------------------------------------------------
    # Create one-time login code
    # -----------------------------------------------------

    login_code = secrets.token_urlsafe(
        32
    )

    LOGIN_CODES[login_code] = session_id

    # -----------------------------------------------------
    # Redirect to Streamlit dashboard
    # -----------------------------------------------------

    redirect_url = (
        f"{DASHBOARD_URL}"
        f"?auth_code={login_code}"
    )

    print(
        f"✅ Google login successful: {email}"
    )

    return RedirectResponse(
        redirect_url
    )


# =========================================================
# EXCHANGE LOGIN CODE
# =========================================================

@app.get("/auth/exchange")
def exchange_auth_code(
    code: str
):

    if not code:

        raise HTTPException(
            status_code=400,
            detail="Missing authentication code"
        )

    session_id = LOGIN_CODES.pop(
        code,
        None
    )

    if not session_id:

        raise HTTPException(
            status_code=401,
            detail="Invalid or expired authentication code"
        )

    session = USER_SESSIONS.get(
        session_id
    )

    if not session:

        raise HTTPException(
            status_code=401,
            detail="Session not found"
        )

    return {

        "session_id": session_id,

        "email": session["email"],

        "name": session["name"]
    }


# =========================================================
# CURRENT USER
# =========================================================

@app.get("/me")
def current_user(
    session_id: str
):

    session = get_session(
        session_id
    )

    return {

        "authenticated": True,

        "email": session["email"],

        "name": session["name"]
    }


# =========================================================
# LOGOUT
# =========================================================

@app.post("/auth/logout")
def logout(
    session_id: str
):

    if session_id in USER_SESSIONS:

        email = USER_SESSIONS[
            session_id
        ].get(
            "email"
        )

        del USER_SESSIONS[
            session_id
        ]

        print(
            f"👋 Logged out: {email}"
        )

    return {
        "message": "Logged out successfully"
    }


# =========================================================
# PREDICT
# =========================================================

class PredictionRequest(BaseModel):

    subject: str = ""

    body: str = ""


@app.post("/predict")
def predict(
    data: PredictionRequest
):

    label, probability = predict_spam(
        data.subject,
        data.body
    )

    return {

        "label": label,

        "spam_probability": round(
            probability,
            4
        ),

        "spam_threshold": SPAM_THRESHOLD
    }


# =========================================================
# GMAIL SCAN
# =========================================================

@app.get("/scan")
def scan_gmail(
    session_id: str,
    max_results: int = 20
):

    session = get_session(
        session_id
    )

    service = get_gmail_service(
        session
    )

    # -----------------------------------------------------
    # Limit max results
    # -----------------------------------------------------

    max_results = max(
        1,
        min(
            max_results,
            50
        )
    )

    try:

        response = service.users().messages().list(
            userId="me",
            maxResults=max_results,
            labelIds=["INBOX"]
        ).execute()

    except Exception as e:

        print(
            f"❌ Gmail list error: {e}"
        )

        raise HTTPException(
            status_code=500,
            detail="Failed to read Gmail messages"
        )

    messages = response.get(
        "messages",
        []
    )

    checked = 0
    spam_count = 0
    ham_count = 0
    trashed_count = 0
    labelled_count = 0

    email_results = []

    # -----------------------------------------------------
    # Process messages
    # -----------------------------------------------------

    for message in messages:

        message_id = message.get(
            "id"
        )

        if not message_id:
            continue

        try:

            full_message = service.users().messages().get(
                userId="me",
                id=message_id,
                format="full"
            ).execute()

            payload = full_message.get(
                "payload",
                {}
            )

            headers = payload.get(
                "headers",
                []
            )

            subject = get_header(
                headers,
                "Subject"
            )

            sender = get_header(
                headers,
                "From"
            )

            body = extract_email_body(
                payload
            )

            label, probability = predict_spam(
                subject,
                body
            )

            checked += 1

            is_spam = (
                probability
                >= SPAM_THRESHOLD
            )

            is_high_confidence_spam = (
                probability
                >= TRASH_THRESHOLD
            )

            # -------------------------------------------------
            # HAM
            # -------------------------------------------------

            if not is_spam:

                ham_count += 1

                action = "KEEP"

            # -------------------------------------------------
            # SPAM
            # -------------------------------------------------

            else:

                spam_count += 1

                action = "LABEL"

                # ---------------------------------------------
                # Create AI-SPAM label if necessary
                # ---------------------------------------------

                try:

                    labels_response = service.users().labels().list(
                        userId="me"
                    ).execute()

                    existing_labels = labels_response.get(
                        "labels",
                        []
                    )

                    spam_label_id = None

                    for gmail_label in existing_labels:

                        if gmail_label.get(
                            "name"
                        ) == SPAM_LABEL:

                            spam_label_id = gmail_label.get(
                                "id"
                            )

                            break

                    if not spam_label_id:

                        created_label = service.users().labels().create(
                            userId="me",
                            body={
                                "name": SPAM_LABEL,
                                "labelListVisibility": "labelShow",
                                "messageListVisibility": "show"
                            }
                        ).execute()

                        spam_label_id = created_label.get(
                            "id"
                        )

                    # -----------------------------------------
                    # Apply AI-SPAM label
                    # -----------------------------------------

                    if spam_label_id:

                        service.users().messages().modify(
                            userId="me",
                            id=message_id,
                            body={
                                "addLabelIds": [
                                    spam_label_id
                                ]
                            }
                        ).execute()

                        labelled_count += 1

                except Exception as e:

                    print(
                        f"⚠️ Label error: {e}"
                    )

                # ---------------------------------------------
                # High-confidence spam → Trash
                # ---------------------------------------------

                if is_high_confidence_spam:

                    try:

                        service.users().messages().trash(
                            userId="me",
                            id=message_id
                        ).execute()

                        trashed_count += 1

                        action = "TRASH"

                    except Exception as e:

                        print(
                            f"⚠️ Trash error: {e}"
                        )

            email_results.append({

                "id": message_id,

                "sender": sender,

                "subject": subject,

                "label": label,

                "spam_probability": round(
                    probability,
                    4
                ),

                "action": action
            })

        except Exception as e:

            print(
                f"⚠️ Email processing error "
                f"{message_id}: {e}"
            )

            continue

    return {

        "count": checked,

        "spam_count": spam_count,

        "ham_count": ham_count,

        "trashed_count": trashed_count,

        "labelled_count": labelled_count,

        "spam_threshold": SPAM_THRESHOLD,

        "trash_threshold": TRASH_THRESHOLD,

        "label": SPAM_LABEL,

        "emails": email_results
    }