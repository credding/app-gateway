from app_gateway.common.tokens import generate_id_token


def generate_idp_id() -> str:
    return generate_id_token("idp_")


def generate_user_id() -> str:
    return generate_id_token("sub_")


def generate_app_id() -> str:
    return generate_id_token("app_")
