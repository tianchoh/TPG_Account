from src.account.utils import generate_username, generate_password, generate_success_code, generate_current_date
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


def register_new_account(user_particulars: Particulars) -> dict:
    """
    Attempts to register a new account. This is the first out of two APIs that should be called in order to register a
    new account for a user. An OTP will be sent to the user's mobile number for authentication, and the second API
    should be called thereafter. The user particulars that are compulsory for this are the user's birth date and mobile
    number, as well as the transaction id of this transaction. This method should not be called directly, but rather
    only with the API call provided in mainapp.
    :param user_particulars: The particulars of the user, which must include birth date, mobile number, and
    transaction id.
    :return: Returns a success code, which must be included in the body of the second API request.
    """
    logger.info("Attempting to register new account.")

    # if not validate_phone_and_dob(user_particulars.get_parameter_value(PARAMETER_NAME_MOBILE_NUMBER), \
    #     user_particulars.get_parameter_value(PARAMETER_NAME_BIRTH_DATE)):
    #     raise InvalidFieldError(error_code=STATUS_1104_DOB_MOBILE_INVALID, error_message=MESSAGE_DOB_MOBILE_INVALID)

    if not user_particulars.contains_all_parameters(*NEW_ACCOUNT_PARAMETER_NAMES):
        raise IncompleteFieldsError(error_code=STATUS_1102_INCOMPLETE_FIELDS, error_message=MESSAGE_INCOMPLETE_FIELDS)
    
    # validate field
    if not user_particulars.validation():
        raise UserConflictError(error_code=STATUS_1107_INVALID_FIELDS, error_message=MESSAGE_INVALID_FIELDS)

    # check if mobile appear that has been authenticate is more than 4x
    user_from_database_count = Storage.get_user_count(user_particulars=user_particulars)

    temp_count = []
    for i in user_from_database_count:
        if i[-1] != None:
            temp_count.append(i)

    print("user found:", len(temp_count))
    if len(temp_count) >=4:
        raise UserConflictError(error_code=STATUS_1106_DOB_EXCEEDED, error_message=MESSAGE_DOB_EXCEEDED)

    user_from_database = Storage.get_user_from_database(user_particulars=user_particulars)

    if not user_from_database.rate_limit():
        raise UserConflictError(error_code=STATUS_1109_OTP_RATE_LIMIT_EXCEEDED, error_message=MESSAGE_OTP_RATE_LIMIT_EXCEEDED)

    # If the user's details already exist, check if they have been authenticated.
    # If they haven't, then replace the existing user's details with the new set.
    if user_from_database.is_present():
        if user_from_database.has_authenticated_account():
            raise UserConflictError(error_code=STATUS_1103_DOB_MOBILE_EXISTS, error_message=MESSAGE_DOB_MOBILE_EXISTS)
        else:
            Storage.clear_existing_user(user_particulars=user_particulars)
    
    
    mobile_number = user_particulars.get_parameter_value(PARAMETER_NAME_MOBILE_NUMBER)
    
    otp, current_timestamp = OTP.generate_otp(mobile_number=mobile_number)
    success_code = generate_success_code()


    user_particulars.set_parameter_value(PARAMETER_NAME_OTP_TIMESTAMP, current_timestamp)
    user_particulars.set_parameter_value(PARAMETER_NAME_OTP, otp)
    user_particulars.set_parameter_value(PARAMETER_NAME_SUCCESS_CODE, success_code)

    create_user_method_success = Storage.create_new_user(user_particulars=user_particulars)
    update_user_method_success = Storage.update_user_in_database(user_particulars=user_particulars)
    if not create_user_method_success or not update_user_method_success:
        raise DatabaseFailureError(error_code=STATUS_1201_CRITICAL_ERROR, error_message=MESSAGE_CRITICAL_ERROR)

    logger.info("Account information stored in database. OTP sent to user. Awaiting authentication.")

    return package_success_code_to_object(success_code)

def send_user_otp(user_particulars: Particulars) -> dict:

    user_from_database = Storage.get_user_from_database(user_particulars=user_particulars)

    otp = user_from_database.get_parameter_value(PARAMETER_NAME_OTP)

    return otp

def authenticate_new_account(user_particulars: Particulars) -> dict:
    """
    Authenticates the registering of a new account. This is the second out of two APIs that should be called in order
    to register a new account for a user. The contents of the input must include the user's birth date and mobile
    number, as well as the success code from the first API. The transaction id and the OTP entered by the user must
    also be included. If successful, the user's account will be created. This method should not be called directly, but
    rather only with the API call provided in mainapp.
    :param user_particulars: The particulars of the user, which must include birth date, mobile number, and also the
    success code, OTP, and transaction id.
    :return: Returns the user's new plaintext username, encrypted username, and encrypted password.
    """
    logger.info("Attempting account authentication for new account.")

    if not user_particulars.contains_all_parameters(*AUTHENTICATION_PARAMETER_NAMES):
        raise IncompleteFieldsError(error_code=STATUS_1102_INCOMPLETE_FIELDS, error_message=MESSAGE_INCOMPLETE_FIELDS)
 
    # validate field
    if not user_particulars.validation():
        raise UserConflictError(error_code=STATUS_1107_INVALID_FIELDS, error_message=MESSAGE_INVALID_FIELDS)

    user_from_database = Storage.get_user_from_database(user_particulars=user_particulars)

    # The user must be present in the database but not authenticated yet - no other combination is valid
    if not user_from_database.is_present():
        raise UserConflictError(error_code=STATUS_1104_DOB_MOBILE_INVALID, error_message=MESSAGE_DOB_MOBILE_INVALID)
    elif user_from_database.has_authenticated_account():
        raise UserConflictError(error_code=STATUS_1103_DOB_MOBILE_EXISTS, error_message=MESSAGE_DOB_MOBILE_EXISTS)

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

    username = generate_username()
    password = generate_password()

    data = {
        'username' : username,
        'password' : password
    }

    Radius_server.create_new_user(data)

    user_particulars.set_parameter_value(PARAMETER_NAME_PLAINTEXT_USERNAME, username)
    user_particulars.set_parameter_value(PARAMETER_NAME_PLAINTEXT_PASSWORD, password)

    nonce = get_random_bytes(12)
    
    nonce = hashlib.sha1(nonce.decode('utf-8', 'replace').encode('utf-8')).hexdigest()

    nonce = bytes(nonce[:12].encode())

    encrypted_username = encode_string(string_to_encode=username, current_date=current_date,
                                       transaction_id=transaction_id, otp=otp, nonce=nonce)
    encrypted_password = encode_string(string_to_encode=password, current_date=current_date,
                                       transaction_id=transaction_id, otp=otp, nonce=nonce)

    update_user_method_success = Storage.update_user_in_database(user_particulars=user_particulars)
    if not update_user_method_success:
        raise DatabaseFailureError(error_code=STATUS_1201_CRITICAL_ERROR, error_message=MESSAGE_CRITICAL_ERROR)

    output_dict = package_username_password_to_object(username=username, encrypted_username=encrypted_username,
                                                      encrypted_password=encrypted_password)

    logger.info("Authentication of new account completed. Account has been created.")

    return output_dict
