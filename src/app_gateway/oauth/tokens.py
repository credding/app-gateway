from app_gateway.common.tokens import generate_id_token, generate_secret_token


def generate_confidential_client_id() -> str:
    return generate_id_token("svc_")


def generate_public_client_id() -> str:
    return generate_id_token("pub_")


def generate_client_secret() -> str:
    return generate_secret_token()


def generate_code_verifier() -> str:
    return generate_secret_token()


def generate_state_token() -> str:
    return generate_secret_token()


def generate_authorization_code() -> str:
    return generate_secret_token()


def generate_refresh_token() -> str:
    return generate_secret_token()
