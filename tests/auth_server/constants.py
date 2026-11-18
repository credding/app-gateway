from datetime import UTC, datetime, timedelta

ISSUER = "https://auth.example.test"
TIME = datetime(2026, 1, 1, tzinfo=UTC)
CREATED_AT = datetime(2025, 1, 1, tzinfo=UTC)
SECRET_ENC_KEY = bytes(range(32))
NONCE_BYTES = bytes(range(12))
TOKEN_SIGNING_SEED = b"test-token-signing-seed-0123456789"
KEY_ROTATION_SCHEDULE = timedelta(days=30)

APP_ID = "app_test"
IDP_ID = "idp_test"
IDP_ISSUER = "https://idp.example.test"
IDP_SUBJECT = "idp-subject-123"
IDP_CLIENT_ID = "idp-client-id"
IDP_CLIENT_SECRET = "idp-client-secret"

CLIENT_ID = "svc_testclient"
CLIENT_SECRET = "client-secret"
PUBLIC_CLIENT_ID = "pub_testclient"
REDIRECT_URI = "https://app.example.test/callback"
CALLBACK_URL = f"{ISSUER}/oauth/broker/test-idp/callback"
RESOURCE = "https://api.example.test"
SCOPE = "openid profile email"
REQUEST_STATE = "client-state"
REQUEST_NONCE = "client-nonce"
USER_ID = "user_test"
SESSION_ID = "session_test"
DEVICE_CODE = "device-code"
