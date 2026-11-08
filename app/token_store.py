import json
import os


BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

TOKEN_FILE = os.path.join(
    BASE_DIR,
    "token.json"
)


def save_token(token):

    with open(
        TOKEN_FILE,
        "w"
    ) as f:

        json.dump(
            token,
            f
        )


def load_token():

    if not os.path.exists(
        TOKEN_FILE
    ):

        return None

    with open(
        TOKEN_FILE,
        "r"
    ) as f:

        return json.load(f)