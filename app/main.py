import os
import json
import base64
import secrets
from datetime import datetime, timedelta, timezone

import joblib

from fastapi import FastAPI, Request
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

TFIDF_PATH = os.path.join(
    BASE_DIR,
    "models",
    "tfidf_vectorizer.pkl"
)

CREDENTIALS_PATH = os.path.join(
    BASE_DIR,
    "credentials.json"
)


# =========================================================
# LOAD ML MODEL
# =========================================================

model = joblib.load(
    MODEL_PATH
)

tfidf = joblib.load(
    TFIDF_PATH
)


# =========================================================
# FASTAPI
# =========================================================

app = FastAPI(
    title="Smart Spam Filter",
    description=(
        "Multi-user AI Gmail Spam "
        "Detection and Cleanup"
    ),
    version="4.0.0"
)


# =========================================================
# SESSION
# =========================================================

SESSION_SECRET = os.getenv(
    "SESSION_SECRET",
    "CHANGE_THIS_SECRET_BEFORE_DEPLOYMENT"
)

app.add_middleware(
    SessionMiddleware,

    secret_key=SESSION_SECRET,

    same_site="lax",

    https_only=False,

    session_cookie="smart_spam_session"
)


# =========================================================
# GOOGLE OAUTH CONFIG
# =========================================================

with open(
    CREDENTIALS_PATH,
    "r"
) as f:

    google_credentials = json.load(f)


web_config = google_credentials["web"]


CLIENT_ID = web_config[
    "client_id"
]

CLIENT_SECRET = web_config[
    "client_secret"
]


# ---------------------------------------------------------
# IMPORTANT
# ---------------------------------------------------------
# Local:
# http://localhost:8000/auth/callback
#
# Later deployment:
# https://YOUR-BACKEND-DOMAIN/auth/callback
# ---------------------------------------------------------

BACKEND_URL = os.getenv(
    "BACKEND_URL",
    "http://localhost:8000"
)

DASHBOARD_URL = os.getenv(
    "DASHBOARD_URL",
    "http://localhost:8501"
)


# =========================================================
# OAUTH
# =========================================================

oauth = OAuth()


oauth.register(

    name="google",

    client_id=CLIENT_ID,

    client_secret=CLIENT_SECRET,

    server_metadata_url=(
        "https://accounts.google.com/"
        ".well-known/openid-configuration"
    ),

    client_kwargs={

        "scope": (
            "openid email profile "
            "https://www.googleapis.com/"
            "auth/gmail.modify"
        )
    }
)


# =========================================================
# SPAM SETTINGS
# =========================================================

SPAM_THRESHOLD = 0.31

# Safer than the previous 0.50
TRASH_THRESHOLD = 0.80


# =========================================================
# TEMPORARY USER SESSION STORE
# =========================================================
#
# This is for local testing.
#
# Later, for public deployment:
# PostgreSQL/Supabase + encrypted tokens.
#
# Structure:
#
# {
#     "random_session_id": {
#         "email": "...",
#         "name": "...",
#         "token": {...},
#         "created_at": ...
#     }
# }
#
# =========================================================

USER_SESSIONS = {}


# =========================================================
# TEMPORARY OAUTH LOGIN CODES
# =========================================================

LOGIN_CODES = {}


# =========================================================
# REQUEST MODEL
# =========================================================

class Email(BaseModel):

    subject: str

    body: str


# =========================================================
# HOME
# =========================================================

@app.get("/")
def home():

    return {

        "message":
            "Smart Spam Filter is running!",

        "version":
            "4.0.0",

        "authentication":
            "Google OAuth",

        "multi_user":
            True,

        "spam_threshold":
            SPAM_THRESHOLD,

        "trash_threshold":
            TRASH_THRESHOLD
    }


# =========================================================
# GOOGLE LOGIN
# =========================================================

@app.get("/auth/login")
async def auth_login(
    request: Request
):

    redirect_uri = (
        BACKEND_URL +
        "/auth/callback"
    )

    return await oauth.google.authorize_redirect(

        request,

        redirect_uri,

        access_type="offline",

        prompt="consent"
    )


# =========================================================
# GOOGLE CALLBACK
# =========================================================

@app.get("/auth/callback")
async def auth_callback(
    request: Request
):

    try:

        # -------------------------------------------------
        # Get Google OAuth token
        # -------------------------------------------------

        token = await (
            oauth.google
            .authorize_access_token(
                request
            )
        )


        # -------------------------------------------------
        # Get Google user information
        # -------------------------------------------------

        user_info = (
            token.get(
                "userinfo"
            )
        )


        if not user_info:

            user_info = await (
                oauth.google
                .userinfo()
            )


        email = user_info.get(
            "email"
        )

        name = user_info.get(
            "name",
            "User"
        )


        if not email:

            return {

                "error":
                    "Google account email "
                    "could not be detected."
            }


        # -------------------------------------------------
        # Create random session ID
        # -------------------------------------------------

        session_id = secrets.token_urlsafe(
            32
        )


        # -------------------------------------------------
        # Store user session
        # -------------------------------------------------

        USER_SESSIONS[
            session_id
        ] = {

            "email":
                email,

            "name":
                name,

            "token":
                token,

            "created_at":
                datetime.now(
                    timezone.utc
                ).isoformat()
        }


        # -------------------------------------------------
        # Create one-time login code
        # -------------------------------------------------

        login_code = secrets.token_urlsafe(
            32
        )


        LOGIN_CODES[
            login_code
        ] = session_id


        print(
            "================================="
        )

        print(
            "✅ Google login successful"
        )

        print(
            "👤 User:",
            email
        )

        print(
            "🔑 User session created"
        )

        print(
            "================================="
        )


        # -------------------------------------------------
        # Redirect to Streamlit
        # -------------------------------------------------

        redirect_url = (
            DASHBOARD_URL
            +
            "?auth_code="
            +
            login_code
        )


        return RedirectResponse(
            redirect_url
        )


    except Exception as e:

        print(
            "❌ Google authentication failed:",
            str(e)
        )

        return {

            "message":
                "Google authentication failed",

            "error":
                str(e)
        }


# =========================================================
# EXCHANGE LOGIN CODE
# =========================================================

@app.get("/auth/exchange")
def exchange_login_code(
    code: str
):

    # -----------------------------------------------------
    # Check code
    # -----------------------------------------------------

    session_id = LOGIN_CODES.pop(
        code,
        None
    )


    if not session_id:

        return {

            "success":
                False,

            "error":
                "Invalid or expired login code."
        }


    # -----------------------------------------------------
    # Check session
    # -----------------------------------------------------

    user = USER_SESSIONS.get(
        session_id
    )


    if not user:

        return {

            "success":
                False,

            "error":
                "User session not found."
        }


    # -----------------------------------------------------
    # Return opaque session ID
    # -----------------------------------------------------

    return {

        "success":
            True,

        "session_id":
            session_id,

        "email":
            user["email"],

        "name":
            user["name"]
    }


# =========================================================
# GET USER
# =========================================================

def get_user_from_session(
    session_id
):

    if not session_id:

        return None


    return USER_SESSIONS.get(
        session_id
    )


# =========================================================
# CREATE GMAIL SERVICE
# =========================================================

def create_gmail_service(
    token
):

    credentials = Credentials(

        token=token.get(
            "access_token"
        ),

        refresh_token=token.get(
            "refresh_token"
        ),

        token_uri=(
            "https://oauth2.googleapis.com/"
            "token"
        ),

        client_id=CLIENT_ID,

        client_secret=CLIENT_SECRET,

        scopes=[
            (
                "https://www.googleapis.com/"
                "auth/gmail.modify"
            )
        ]
    )


    return build(
        "gmail",
        "v1",
        credentials=credentials
    )


# =========================================================
# GET USER GMAIL SERVICE
# =========================================================

def get_gmail_service_from_session(
    session_id
):

    user = get_user_from_session(
        session_id
    )


    if not user:

        return None


    token = user.get(
        "token"
    )


    if not token:

        return None


    return create_gmail_service(
        token
    )


# =========================================================
# LOGOUT
# =========================================================

@app.post("/auth/logout")
def logout(
    session_id: str
):

    if session_id in USER_SESSIONS:

        user = USER_SESSIONS.pop(
            session_id
        )

        print(
            "👋 Logged out:",
            user.get(
                "email"
            )
        )


    return {

        "success":
            True,

        "message":
            "Logged out successfully."
    }


# =========================================================
# USER PROFILE
# =========================================================

@app.get("/me")
def get_me(
    session_id: str
):

    user = get_user_from_session(
        session_id
    )


    if not user:

        return {

            "authenticated":
                False,

            "message":
                "Please login with Google."
        }


    return {

        "authenticated":
            True,

        "name":
            user["name"],

        "email":
            user["email"],

        "created_at":
            user["created_at"]
    }


# =========================================================
# EMAIL BODY
# =========================================================

def extract_email_body(
    payload
):

    if not payload:

        return ""


    # -----------------------------------------------------
    # Direct body
    # -----------------------------------------------------

    body = payload.get(
        "body",
        {}
    )


    data = body.get(
        "data"
    )


    if data:

        try:

            return (
                base64
                .urlsafe_b64decode(
                    data
                )
                .decode(
                    "utf-8",
                    errors="ignore"
                )
            )

        except Exception:

            return ""


    # -----------------------------------------------------
    # Multipart
    # -----------------------------------------------------

    parts = payload.get(
        "parts",
        []
    )


    for part in parts:

        mime_type = part.get(
            "mimeType",
            ""
        )


        # Plain text

        if mime_type == "text/plain":

            data = (
                part
                .get(
                    "body",
                    {}
                )
                .get(
                    "data"
                )
            )


            if data:

                try:

                    return (
                        base64
                        .urlsafe_b64decode(
                            data
                        )
                        .decode(
                            "utf-8",
                            errors="ignore"
                        )
                    )

                except Exception:

                    return ""


        # Nested multipart

        if part.get(
            "parts"
        ):

            result = (
                extract_email_body(
                    part
                )
            )


            if result:

                return result


    return ""


# =========================================================
# EMAIL HEADERS
# =========================================================

def get_email_headers(
    payload
):

    headers = {}


    for header in payload.get(
        "headers",
        []
    ):

        name = header.get(
            "name",
            ""
        ).lower()

        value = header.get(
            "value",
            ""
        )


        if name in [
            "from",
            "subject"
        ]:

            headers[name] = value


    return headers


# =========================================================
# ML PREDICTION
# =========================================================

def predict_text(
    subject,
    body
):

    email_text = (
        subject +
        " " +
        body
    )


    email_tfidf = (
        tfidf.transform(
            [email_text]
        )
    )


    probabilities = (
        model.predict_proba(
            email_tfidf
        )[0]
    )


    spam_probability = float(
        probabilities[1]
    )


    ham_probability = float(
        probabilities[0]
    )


    # -----------------------------------------------------
    # Decision
    # -----------------------------------------------------

    if (
        spam_probability
        >= TRASH_THRESHOLD
    ):

        prediction = "SPAM"

        action = "TRASH"


    elif (
        spam_probability
        >= SPAM_THRESHOLD
    ):

        prediction = "SPAM"

        action = "AI-SPAM"


    else:

        prediction = "HAM"

        action = "NONE"


    confidence = max(
        spam_probability,
        ham_probability
    )


    return {

        "prediction":
            prediction,

        "spam_probability":
            round(
                spam_probability,
                4
            ),

        "ham_probability":
            round(
                ham_probability,
                4
            ),

        "confidence":
            round(
                confidence,
                4
            ),

        "action":
            action
    }


# =========================================================
# AI-SPAM LABEL
# =========================================================

def get_or_create_spam_label(
    gmail_service
):

    response = (

        gmail_service
        .users()
        .labels()
        .list(
            userId="me"
        )
        .execute()
    )


    labels = response.get(
        "labels",
        []
    )


    for label in labels:

        if (
            label.get("name")
            == "AI-SPAM"
        ):

            return label.get(
                "id"
            )


    label_body = {

        "name":
            "AI-SPAM",

        "labelListVisibility":
            "labelShow",

        "messageListVisibility":
            "show"
    }


    created_label = (

        gmail_service
        .users()
        .labels()
        .create(

            userId="me",

            body=label_body

        )
        .execute()
    )


    return created_label.get(
        "id"
    )


# =========================================================
# SCAN GMAIL
# =========================================================

def scan_gmail_emails(
    gmail_service
):

    messages_response = (

        gmail_service
        .users()
        .messages()
        .list(

            userId="me",

            maxResults=20

        )
        .execute()
    )


    messages = (
        messages_response
        .get(
            "messages",
            []
        )
    )


    if not messages:

        return {

            "count":
                0,

            "new_count":
                0,

            "spam_count":
                0,

            "trash_count":
                0,

            "labelled_count":
                0,

            "ham_count":
                0,

            "spam_threshold":
                SPAM_THRESHOLD,

            "trash_threshold":
                TRASH_THRESHOLD,

            "label":
                "AI-SPAM",

            "emails":
                []
        }


    spam_label_id = (
        get_or_create_spam_label(
            gmail_service
        )
    )


    results = []


    spam_count = 0

    trash_count = 0

    labelled_count = 0

    ham_count = 0


    # =====================================================
    # PROCESS EMAILS
    # =====================================================

    for message in messages:

        message_id = message.get(
            "id"
        )


        try:

            email_data = (

                gmail_service
                .users()
                .messages()
                .get(

                    userId="me",

                    id=message_id,

                    format="full"

                )
                .execute()
            )


            payload = email_data.get(
                "payload",
                {}
            )


            headers = (
                get_email_headers(
                    payload
                )
            )


            sender = headers.get(
                "from",
                ""
            )


            subject = headers.get(
                "subject",
                ""
            )


            body = (
                extract_email_body(
                    payload
                )
            )


            prediction = predict_text(

                subject,

                body
            )


            is_spam = (
                prediction[
                    "prediction"
                ]
                == "SPAM"
            )


            label_applied = False

            moved_to_trash = False


            # =================================================
            # SPAM
            # =================================================

            if is_spam:

                spam_count += 1


                # -------------------------------------------------
                # TRASH
                # -------------------------------------------------

                if (
                    prediction["action"]
                    == "TRASH"
                ):

                    (
                        gmail_service
                        .users()
                        .messages()
                        .trash(

                            userId="me",

                            id=message_id

                        )
                        .execute()
                    )


                    trash_count += 1

                    moved_to_trash = True


                    print(
                        "🗑️ TRASHED:",
                        subject,
                        "|",
                        prediction[
                            "spam_probability"
                        ]
                    )


                # -------------------------------------------------
                # AI-SPAM
                # -------------------------------------------------

                else:

                    (
                        gmail_service
                        .users()
                        .messages()
                        .modify(

                            userId="me",

                            id=message_id,

                            body={
                                "addLabelIds":
                                    [spam_label_id]
                            }

                        )
                        .execute()
                    )


                    labelled_count += 1

                    label_applied = True


                    print(
                        "🏷️ AI-SPAM:",
                        subject,
                        "|",
                        prediction[
                            "spam_probability"
                        ]
                    )


            else:

                ham_count += 1


                print(
                    "✅ HAM:",
                    subject,
                    "|",
                    prediction[
                        "spam_probability"
                    ]
                )


            results.append({

                "id":
                    message_id,

                "from":
                    sender,

                "subject":
                    subject,

                "prediction":
                    prediction[
                        "prediction"
                    ],

                "spam_probability":
                    prediction[
                        "spam_probability"
                    ],

                "ham_probability":
                    prediction[
                        "ham_probability"
                    ],

                "confidence":
                    prediction[
                        "confidence"
                    ],

                "action":
                    prediction[
                        "action"
                    ],

                "label_applied":
                    label_applied,

                "moved_to_trash":
                    moved_to_trash
            })


        except Exception as e:

            print(
                "❌ Email processing error:",
                message_id,
                str(e)
            )


            results.append({

                "id":
                    message_id,

                "error":
                    str(e)
            })


    # =====================================================
    # RESPONSE
    # =====================================================

    return {

        "count":
            len(messages),

        "new_count":
            len(results),

        "spam_count":
            spam_count,

        "trash_count":
            trash_count,

        "labelled_count":
            labelled_count,

        "ham_count":
            ham_count,

        "spam_threshold":
            SPAM_THRESHOLD,

        "trash_threshold":
            TRASH_THRESHOLD,

        "label":
            "AI-SPAM",

        "emails":
            results
    }


# =========================================================
# SCAN
# =========================================================

@app.get("/scan")
def scan_emails(
    session_id: str
):

    gmail_service = (
        get_gmail_service_from_session(
            session_id
        )
    )


    if not gmail_service:

        return {

            "error":
                "Authentication expired. "
                "Please login again."
        }


    try:

        return scan_gmail_emails(
            gmail_service
        )

    except Exception as e:

        return {

            "error":
                str(e)
        }


# =========================================================
# MANUAL ML PREDICTION
# =========================================================

@app.post("/predict")
def predict_email(
    email: Email
):

    result = predict_text(

        email.subject,

        email.body
    )


    return {

        "prediction":
            result["prediction"],

        "spam_probability":
            result["spam_probability"],

        "ham_probability":
            result["ham_probability"],

        "confidence":
            result["confidence"],

        "action":
            result["action"],

        "spam_threshold":
            SPAM_THRESHOLD,

        "trash_threshold":
            TRASH_THRESHOLD
    }


# =========================================================
# HEALTH CHECK
# =========================================================

@app.get("/health")
def health():

    return {

        "status":
            "healthy",

        "service":
            "Smart Spam Filter",

        "multi_user":
            True,

        "ml_model":
            "TF-IDF + Logistic Regression"
    }