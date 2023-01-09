from datetime import date
from random import randint
import string
import random
import secrets
from src.account.commons import *
from src.commons.logging import create_logger

from test.commons.sample_data import SAMPLE_USERNAME_1


logger = create_logger(__name__)

#def is_hex(transaction_hex):
#    return re.fullmatch(r"^[0-9a-fA-F]$", transaction_hex or "") is not None

def generate_username() -> str:
    random_integer = secrets.randbelow(USERNAME_MAX_INT+1)
    padded_random_integer = str(random_integer).rjust(USERNAME_MAX_INT_LENGTH, "0")
    return "essa-" + padded_random_integer + "@tpg"


def generate_password() -> str:
    # MAX LENGTH 32
    # 1 Uppercase Aplhabet
    # 1 Lowercase Aplhabet
    # 1 Numeral
    # 1 Special Character
    special_char = "!@%/()=?+.-"
    all_chars = string.ascii_lowercase + \
        string.digits + \
        string.ascii_uppercase + \
        special_char
    password_string = ''.join(secrets.choice(all_chars) for i in range(32))
    return password_string

def generate_current_date() -> str:
    """
    Generates the current date, in the format DDMMYYYY.
    :return: Returns the current date, in a string with format DDMMYYYY.
    """
    current_date_as_datetime = date.today()
    current_date_as_string = current_date_as_datetime.strftime(DATE_FORMAT)

    logger.debug("Generated current date: {}".format(current_date_as_string))
    return current_date_as_string


def generate_success_code() -> str:
    """
    Generates a random success code. Success codes are random integer strings of any value from 0 to a fixed MAX_INT.
    The output string will be padded with 0s from the start, so the length will always be the same.
    :return:
    """
    random_integer = secrets.randbelow(SUCCESS_CODE_MAX_INT+1)
    padded_random_integer = str(random_integer).rjust(SUCCESS_CODE_MAX_INT_LENGTH, "0")

    logger.debug("Generated success code: {}".format(padded_random_integer))
    return padded_random_integer

def validate_mobile_number(mobile_number):

    # Only numeric with one dash “-“ to separate country code and phone number
    temp = ''.join([i for i in mobile_number if not i.isdigit()])
    if temp != "-":
        return False

    C, N = mobile_number.split('-')
    if not C.isdigit() or not N.isdigit():
        return False
        
    # Country code = C (max 4 digits)
    if len(C) < 1 or len(C) > 4:
        return False

    # Phone Number = N (max 16 digits)
    if len(N) < 1 or len(N) > 16:
        return False

    return True

def validate_birth_date(birth_date):

    # only numeric
    if not birth_date.isdigit():
        return False

    # only 8 digits
    if len(birth_date) != 8:
        return False

    # DD = 01 to 31
    DD = int(birth_date[0:2])
    if DD < 1 or DD > 31:
        return False

    # MM = 01 to 12
    MM = int(birth_date[2:4])
    if MM < 1 or MM > 12:
        return False

    # YYYY = 1990 to 2030
    YYYY = int(birth_date[4:8])
    if YYYY < 1900 or YYYY > 2040:
        return False

    return True

def validate_transaction_id(transaction_id):

    # Only numeric
    if not transaction_id.isalnum(): 
        return False

    # Only 24 digits
    if len(transaction_id) != 24:
        return False

    return True

def validate_success_code(success_code):

    # Only numeric
    if not success_code.isdigit():
        return False

    # Only  digits
    if len(success_code) != 16:
        return False

    return True

def validate_otp(otp):

    # Only numeric
    if not otp.isdigit():
        return False

    # Only  digits
    if len(otp) != 6:
        return False

    return True

def validate_username(username):

    # Must start with “essa-“
    start = username[0:5]
    if start != "essa-":
        return False

    # Must end with “@tpg”
    end = username[-4:]
    if end != "@tpg":
        return False

    return True

def validate_password(password):

    # Must contain 32 characters
    if len(password) != 32:
        return False

    return True

def validate_device_type(device_type):

    # Must be “1”
    if str(device_type) != "1":
        return False
    
    return True
