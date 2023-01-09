from src.account.utils import generate_password, generate_success_code, generate_current_date
from src.commons.errors import IncompleteFieldsError, InvalidFieldError, UserConflictError, DatabaseFailureError
from src.commons.ioutils import package_username_password_to_object, package_success_code_to_object
from src.commons.logging import create_logger
from src.commons.messages import *
from src.commons.parameters import *
from src.commons.particulars import Particulars
from src.encryption.encryptor import encode_string
from src.encryption.otp import OTP
from src.storage.storage import Storage
from src.readtxt.readtxt import validate_phone_and_dob
from src.radius_server.radius_server import Radius_server
import hashlib
from Cryptodome.Random import get_random_bytes

logger = create_logger(__name__)


def reset_user_password(user_particulars: Particulars) -> dict:
    """
    Attempts to reset a user's password. This is the first out of two APIs that should be called in order to reset the
    password of a user. An OTP will be sent to the user's mobile number for authentication, and the second API
    should be called thereafter. The user particulars that are compulsory for this are the user's birth date and mobile
    number, as well as the transaction id of this transaction. This method should not be called directly, but rather
    only with the API call provided in mainapp.
    :param user_particulars: The particulars of the user, which must include birth date, mobile number, and
    transaction id.
    :return: Returns a success code, which must be included in the body of the second API request.
    """
    logger.info("Attempting to reset user password.")

    if not user_particulars.contains_all_parameters(*PASSWORD_RETRIEVE_RESET_PARAMETER_NAMES):
        raise IncompleteFieldsError(error_code=STATUS_1102_INCOMPLETE_FIELDS, error_message=MESSAGE_INCOMPLETE_FIELDS)

    # validate field
    if not user_particulars.validation():
        raise UserConflictError(error_code=STATUS_1107_INVALID_FIELDS, error_message=MESSAGE_INVALID_FIELDS)

    # if not validate_phone_and_dob(user_particulars.get_parameter_value(PARAMETER_NAME_MOBILE_NUMBER), \
    #     user_particulars.get_parameter_value(PARAMETER_NAME_BIRTH_DATE)):
    #     raise InvalidFieldError(error_code=STATUS_1104_DOB_MOBILE_INVALID, error_message=MESSAGE_DOB_MOBILE_INVALID)

    user_from_database = Storage.get_user_from_database(user_particulars=user_particulars)

    if not user_from_database.rate_limit():
        raise UserConflictError(error_code=STATUS_1109_OTP_RATE_LIMIT_EXCEEDED, error_message=MESSAGE_OTP_RATE_LIMIT_EXCEEDED)

    if not user_from_database.is_present() or not user_from_database.has_authenticated_account():
        raise UserConflictError(error_code=STATUS_1104_DOB_MOBILE_INVALID, error_message=MESSAGE_DOB_MOBILE_INVALID)

    mobile_number = user_particulars.get_parameter_value(PARAMETER_NAME_MOBILE_NUMBER)
    otp, current_timestamp = OTP.generate_otp(mobile_number=mobile_number)
    success_code = generate_success_code()
    user_particulars.set_parameter_value(PARAMETER_NAME_OTP_TIMESTAMP, current_timestamp)
    user_particulars.set_parameter_value(PARAMETER_NAME_OTP, otp)
    user_particulars.set_parameter_value(PARAMETER_NAME_SUCCESS_CODE, success_code)

    update_user_method_success = Storage.update_user_in_database(user_particulars=user_particulars)
    if not update_user_method_success:
        raise DatabaseFailureError(error_code=STATUS_1201_CRITICAL_ERROR, error_message=MESSAGE_CRITICAL_ERROR)

    logger.info("User has been identified. OTP sent to user. Awaiting authentication.")

    return package_success_code_to_object(success_code)


def authenticate_password_reset(user_particulars: Particulars) -> dict:
    """
    Authenticates the resetting of a user's password. This is the second out of two APIs that should be called in order
    to reset the password of an existing user. The contents of the input must include the user's birth date and mobile
    number, as well as the success code from the first API. The transaction id and the OTP entered by the user must
    also be included. If successful, the user's account will be created. This method should not be called directly, but
    rather only with the API call provided in mainapp.
    :param user_particulars: The particulars of the user, which must include birth date, mobile number, and also the
    success code, OTP, and transaction id.
    :return: Returns the user's new plaintext username, encrypted username, and encrypted password.
    """
    logger.info("Attempting account authentication for user password reset.")

    if not user_particulars.contains_all_parameters(*AUTHENTICATION_PARAMETER_NAMES):
        raise IncompleteFieldsError(error_code=STATUS_1102_INCOMPLETE_FIELDS, error_message=MESSAGE_INCOMPLETE_FIELDS)

    # validate field
    if not user_particulars.validation():
        raise UserConflictError(error_code=STATUS_1107_INVALID_FIELDS, error_message=MESSAGE_INVALID_FIELDS)


    user_from_database = Storage.get_user_from_database(user_particulars=user_particulars)

    if not user_from_database.is_present() or not user_from_database.has_authenticated_account():
        raise UserConflictError(error_code=STATUS_1104_DOB_MOBILE_INVALID, error_message=MESSAGE_DOB_MOBILE_INVALID)

    success_code = user_particulars.get_parameter_value(PARAMETER_NAME_SUCCESS_CODE)
    otp = user_particulars.get_parameter_value(PARAMETER_NAME_OTP)

    if user_from_database.get_parameter_value(PARAMETER_NAME_SUCCESS_CODE) != success_code:
        raise InvalidFieldError(error_code=STATUS_1106_INVALID_SUCCESS_CODE, error_message=MESSAGE_INVALID_SUCCESS_CODE)
    elif user_from_database.get_parameter_value(PARAMETER_NAME_OTP) != otp:
        raise InvalidFieldError(error_code=STATUS_1105_INVALID_OTP, error_message=MESSAGE_INVALID_OTP)

    # check otp expiry
    if not user_from_database.otp_expiry():
        raise UserConflictError(error_code=STATUS_1108_OTP_EXPIRED, error_message=MESSAGE_OTP_EXPIRED)

    transaction_id = user_particulars.get_parameter_value(PARAMETER_NAME_TRANSACTION_ID)

    current_date = generate_current_date()

    username = user_from_database.get_parameter_value(PARAMETER_NAME_PLAINTEXT_USERNAME)
    password = generate_password()

    data = {
        'username' : username,
        'password' : password
    }

    Radius_server.update_user_in_database(data)

    user_particulars.set_parameter_value(PARAMETER_NAME_PLAINTEXT_USERNAME, username)
    user_particulars.set_parameter_value(PARAMETER_NAME_PLAINTEXT_PASSWORD, password)

    update_user_method_success = Storage.update_user_in_database(user_particulars=user_particulars)
    if not update_user_method_success:
        raise DatabaseFailureError(error_code=STATUS_1201_CRITICAL_ERROR, error_message=MESSAGE_CRITICAL_ERROR)


    nonce = get_random_bytes(12)
    
    nonce = hashlib.sha1(nonce.decode('utf-8', 'replace').encode('utf-8')).hexdigest()

    nonce = bytes(nonce[:12].encode())

    encrypted_username = encode_string(string_to_encode=username, current_date=current_date,
                                       transaction_id=transaction_id, otp=otp, nonce=nonce)
    encrypted_password = encode_string(string_to_encode=password, current_date=current_date,
                                       transaction_id=transaction_id, otp=otp, nonce=nonce)

    output_dict = package_username_password_to_object(username=username, encrypted_username=encrypted_username,
                                                      encrypted_password=encrypted_password)

    logger.info("Authentication of password reset completed.")

    return output_dict
