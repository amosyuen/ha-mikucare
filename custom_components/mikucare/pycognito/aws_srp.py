import base64
import binascii
import datetime
import hashlib
import hmac
import os

from .exceptions import DeviceSrpAuthChallengeException
from .exceptions import ForceChangePasswordException
from .exceptions import SMSMFAChallengeException
from .exceptions import SoftwareTokenMFAChallengeException

# https://github.com/aws/amazon-cognito-identity-js/blob/master/src/AuthenticationHelper.js#L22
N_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
    "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
    "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
    "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
    "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF"
)
# https://github.com/aws/amazon-cognito-identity-js/blob/master/src/AuthenticationHelper.js#L49
G_HEX = "2"
INFO_BITS = bytearray("Caldera Derived Key", "utf-8")
WEEKDAY_NAMES = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
MONTH_NAMES = [
    "Jan",
    "Feb",
    "Mar",
    "Apr",
    "May",
    "Jun",
    "Jul",
    "Aug",
    "Sep",
    "Oct",
    "Nov",
    "Dec",
]
SALT_BYTES = 16
DEVICE_PASSWORD_BYTES = 40


def hash_sha256(buf):
    """AuthenticationHelper.hash"""
    value = hashlib.sha256(buf).hexdigest()
    return (64 - len(value)) * "0" + value


def hex_hash(hex_string):
    return hash_sha256(bytearray.fromhex(hex_string))


def hex_to_long(hex_string):
    return int(hex_string, 16)


def long_to_hex(long_num):
    return f"{long_num:x}"


def get_random(nbytes):
    random_hex = binascii.hexlify(os.urandom(nbytes))
    return hex_to_long(random_hex)


def pad_hex(long_int):
    """
    Converts a Long integer (or hex string) to hex format padded with zeroes for hashing
    :param {Long integer|String} long_int Number or string to pad.
    :return {String} Padded hex string.
    """
    if not isinstance(long_int, str):
        hash_str = long_to_hex(long_int)
    else:
        hash_str = long_int
    if len(hash_str) % 2 == 1:
        hash_str = f"0{hash_str}"
    elif hash_str[0] in "89ABCDEFabcdef":
        hash_str = f"00{hash_str}"
    return hash_str


def hex_to_base64(hex):
    return base64.standard_b64encode(bytearray.fromhex(hex)).decode("utf-8")


def compute_hkdf(ikm, salt):
    """
    Standard hkdf algorithm
    :param {Buffer} ikm Input key material.
    :param {Buffer} salt Salt value.
    :return {Buffer} Strong key material.
    @private
    """
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    info_bits_update = INFO_BITS + bytearray(chr(1), "utf-8")
    hmac_hash = hmac.new(prk, info_bits_update, hashlib.sha256).digest()
    return hmac_hash[:16]


def calculate_u(big_a, big_b):
    """
    Calculate the client's value U which is the hash of A and B
    :param {Long integer} big_a Large A value.
    :param {Long integer} big_b Server B value.
    :return {Long integer} Computed U value.
    """
    u_hex_hash = hex_hash(pad_hex(big_a) + pad_hex(big_b))
    return hex_to_long(u_hex_hash)


class AWSSRP:
    DEVICE_PASSWORD_VERIFIER_CHALLENGE = "DEVICE_PASSWORD_VERIFIER"
    DEVICE_SRP_AUTH_CHALLENGE = "DEVICE_SRP_AUTH"
    SMS_MFA_CHALLENGE = "SMS_MFA"
    SOFTWARE_TOKEN_MFA_CHALLENGE = "SOFTWARE_TOKEN_MFA"
    NEW_PASSWORD_REQUIRED_CHALLENGE = "NEW_PASSWORD_REQUIRED"
    PASSWORD_VERIFIER_CHALLENGE = "PASSWORD_VERIFIER"

    def __init__(
        self,
        group_id,
        username,
        password,
        client_id,
        client,
        key=None,
        device_key=None,
        client_secret=None,
    ):
        self.username = username
        self.key = key or username
        self.password = password
        self.group_id = group_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.device_key = device_key
        self.client = client
        self.big_n = hex_to_long(N_HEX)
        self.val_g = hex_to_long(G_HEX)
        self.val_k = hex_to_long(hex_hash("00" + N_HEX + "0" + G_HEX))
        self.small_a_value = self.generate_random_small_a()
        self.large_a_value = self.calculate_a()

    def generate_random_small_a(self):
        """
        helper function to generate a random big integer
        :return {Long integer} a random value.
        """
        random_long_int = get_random(128)
        return random_long_int % self.big_n

    def calculate_a(self):
        """
        Calculate the client's public value A = g^a%N
        with the generated random number a
        :param {Long integer} a Randomly generated small A.
        :return {Long integer} Computed large A.
        """
        big_a = pow(self.val_g, self.small_a_value, self.big_n)
        # safety check
        if (big_a % self.big_n) == 0:
            raise ValueError("Safety check for A failed")
        return big_a

    def calculate_x_and_verifier(self, salt):
        """
        Calculates x and verifier values
        :param {Long integer} server_b_value Server B value.
        :param {Long integer} salt Generated salt.
        :return {x} and {verifier}
        """
        username_password = f"{self.group_id}{self.key}:{self.password}"
        username_password_hash = hash_sha256(username_password.encode("utf-8"))
        x_value = hex_to_long(hex_hash(pad_hex(salt) + username_password_hash))
        verifier = pow(self.val_g, x_value, self.big_n)
        return x_value, verifier

    def get_password_authentication_key(self, server_b_value, salt):
        """
        Calculates the final hkdf based on computed S value, and computed U value and the key
        :param {Long integer} server_b_value Server B value.
        :param {Long integer} salt Generated salt.
        :return {Buffer} Computed HKDF value.
        """
        x_value, g_mod_pow_xn = self.calculate_x_and_verifier(salt)
        int_value2 = server_b_value - self.val_k * g_mod_pow_xn

        u_value = calculate_u(self.large_a_value, server_b_value)
        if u_value == 0:
            raise ValueError("U cannot be zero.")
        s_value = pow(int_value2, self.small_a_value + u_value * x_value, self.big_n)
        hkdf = compute_hkdf(
            bytearray.fromhex(pad_hex(s_value)),
            bytearray.fromhex(pad_hex(long_to_hex(u_value))),
        )
        return hkdf

    def get_secret_verifier_config(self):
        salt_hex = self.generate_salt_hex()
        _, verifier = self.calculate_x_and_verifier(salt_hex)
        return {
            "PasswordVerifier": hex_to_base64(pad_hex(verifier)),
            "Salt": hex_to_base64(salt_hex),
        }

    def get_auth_params(self):
        auth_params = {
            "USERNAME": self.username,
            "SRP_A": long_to_hex(self.large_a_value),
        }
        if self.client_secret is not None:
            auth_params.update(
                {
                    "SECRET_HASH": self.get_secret_hash(
                        self.username, self.client_id, self.client_secret
                    )
                }
            )
        if self.device_key is not None:
            auth_params["DEVICE_KEY"] = self.device_key
        return auth_params

    @staticmethod
    def get_secret_hash(username, client_id, client_secret):
        message = bytearray(username + client_id, "utf-8")
        hmac_obj = hmac.new(bytearray(client_secret, "utf-8"), message, hashlib.sha256)
        return base64.standard_b64encode(hmac_obj.digest()).decode("utf-8")

    @staticmethod
    def generate_device_password():
        return base64.standard_b64encode(os.urandom(DEVICE_PASSWORD_BYTES)).decode(
            "utf-8"
        )

    @staticmethod
    def generate_salt_hex():
        return pad_hex(get_random(SALT_BYTES))

    @staticmethod
    def get_cognito_formatted_timestamp(input_datetime):
        return f"{WEEKDAY_NAMES[input_datetime.weekday()]} {MONTH_NAMES[input_datetime.month - 1]} {input_datetime.day:d} {input_datetime.hour:02d}:{input_datetime.minute:02d}:{input_datetime.second:02d} UTC {input_datetime.year:d}"

    def process_password_challenge(self, challenge_parameters):
        salt_hex = challenge_parameters["SALT"]
        srp_b_hex = challenge_parameters["SRP_B"]
        secret_block_b64 = challenge_parameters["SECRET_BLOCK"]
        timestamp = self.get_cognito_formatted_timestamp(datetime.datetime.utcnow())
        hkdf = self.get_password_authentication_key(hex_to_long(srp_b_hex), salt_hex)
        secret_block_bytes = base64.standard_b64decode(secret_block_b64)
        msg = (
            bytearray(self.group_id, "utf-8")
            + bytearray(self.key, "utf-8")
            + bytearray(secret_block_bytes)
            + bytearray(timestamp, "utf-8")
        )

        hmac_obj = hmac.new(hkdf, msg, digestmod=hashlib.sha256)
        signature_string = base64.standard_b64encode(hmac_obj.digest())
        response = {
            "TIMESTAMP": timestamp,
            "USERNAME": self.username,
            "PASSWORD_CLAIM_SECRET_BLOCK": secret_block_b64,
            "PASSWORD_CLAIM_SIGNATURE": signature_string.decode("utf-8"),
        }
        if self.client_secret is not None:
            response.update(
                {
                    "SECRET_HASH": self.get_secret_hash(
                        self.username, self.client_id, self.client_secret
                    )
                }
            )
        if self.device_key:
            response["DEVICE_KEY"] = self.device_key
        return response

    def authenticate_user(self, client_metadata=None):
        auth_params = self.get_auth_params()
        response = self.client.initiate_auth(
            AuthFlow="USER_SRP_AUTH",
            AuthParameters=auth_params,
            ClientId=self.client_id,
        )
        challenge_params = response["ChallengeParameters"]
        if "USERNAME" in challenge_params:
            self.username = self.key = challenge_params["USERNAME"]
        if response["ChallengeName"] == self.PASSWORD_VERIFIER_CHALLENGE:
            challenge_response = self.process_password_challenge(
                challenge_params,
            )
            response = self.client.respond_to_auth_challenge(
                ClientId=self.client_id,
                ChallengeName=self.PASSWORD_VERIFIER_CHALLENGE,
                ChallengeResponses=challenge_response,
                **dict(ClientMetadata=client_metadata) if client_metadata else {},
            )

            if response.get("ChallengeName") == self.NEW_PASSWORD_REQUIRED_CHALLENGE:
                raise ForceChangePasswordException(
                    "Change password before authenticating"
                )

            if response.get("ChallengeName") == self.SMS_MFA_CHALLENGE:
                raise SMSMFAChallengeException("Do SMS MFA", response)

            if response.get("ChallengeName") == self.SOFTWARE_TOKEN_MFA_CHALLENGE:
                raise SoftwareTokenMFAChallengeException(
                    "Do Software Token MFA", response
                )

            if response.get("ChallengeName") == self.DEVICE_SRP_AUTH_CHALLENGE:
                raise DeviceSrpAuthChallengeException("Do device auth")

        if response.get("ChallengeName") is not None:
            raise NotImplementedError(
                f"The {response['ChallengeName']} challenge is not supported"
            )

        return response

    def authenticate_device(self, client_metadata=None):
        challenge_response = self.get_auth_params()
        challenge_response["SRP_A"] = long_to_hex(self.large_a_value)
        response = self.client.respond_to_auth_challenge(
            ClientId=self.client_id,
            ChallengeName=self.DEVICE_SRP_AUTH_CHALLENGE,
            ChallengeResponses=challenge_response,
            **dict(ClientMetadata=client_metadata) if client_metadata else {},
        )

        if response.get("ChallengeName") == self.DEVICE_PASSWORD_VERIFIER_CHALLENGE:
            challenge_response = self.process_password_challenge(
                response["ChallengeParameters"],
            )
            response = self.client.respond_to_auth_challenge(
                ClientId=self.client_id,
                ChallengeName=self.DEVICE_PASSWORD_VERIFIER_CHALLENGE,
                ChallengeResponses=challenge_response,
                **dict(ClientMetadata=client_metadata) if client_metadata else {},
            )

        if response.get("ChallengeName") is not None:
            raise NotImplementedError(
                f"The {response['ChallengeName']} challenge is not supported"
            )

        return response

    def set_new_password_challenge(self, new_password):
        auth_params = self.get_auth_params()
        response = self.client.initiate_auth(
            AuthFlow="USER_SRP_AUTH",
            AuthParameters=auth_params,
            ClientId=self.client_id,
        )

        if response["ChallengeName"] == self.PASSWORD_VERIFIER_CHALLENGE:
            challenge_response = self.process_password_challenge(
                response["ChallengeParameters"],
            )
            response = self.client.respond_to_auth_challenge(
                ClientId=self.client_id,
                ChallengeName=self.PASSWORD_VERIFIER_CHALLENGE,
                ChallengeResponses=challenge_response,
            )

            if response["ChallengeName"] == self.NEW_PASSWORD_REQUIRED_CHALLENGE:
                challenge_parameters = response["ChallengeParameters"]
                challenge_response.update(
                    {
                        "USERNAME": challenge_parameters["USERNAME"],
                        "NEW_PASSWORD": new_password,
                    }
                )
                new_password_response = self.client.respond_to_auth_challenge(
                    ClientId=self.client_id,
                    ChallengeName=self.NEW_PASSWORD_REQUIRED_CHALLENGE,
                    Session=response["Session"],
                    ChallengeResponses=challenge_response,
                )
                return new_password_response

        if response.get("ChallengeName") is not None:
            raise NotImplementedError(
                f"The {response['ChallengeName']} challenge is not supported"
            )

        return response
