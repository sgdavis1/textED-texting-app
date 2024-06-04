import argparse
import json
import logging
import re
import os
import sentry_sdk
import sys

from boto3 import session
from botocore.exceptions import ClientError
from datetime import datetime
from dotenv import load_dotenv
from enum import Enum
from rapidfuzz.fuzz import partial_ratio
from sentry_sdk.integrations.logging import LoggingIntegration
from twilio.rest import Client
from urllib.parse import urlparse

# Helpful modules for development
import inspect
from pprint import pprint


class MessageType(Enum):
    FIRST = 0
    OPT_IN_MISSING = 1
    RECENT_REPLY = 2
    LATER_REPLY = 3


# Match Threshold (to determine messages that cannot be handled)
MATCH_MISSING_THRESHOLD = 60
MATCH_UNCERTAIN_THRESHOLD = 75

# Consistent format for reading / writing datetime strings
DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S"
RECENT_LIMIT_MINUTES = 30
# Configure all ENV settings
load_dotenv()


# Sentry setup from config: [critical, error, warning, info, debug]
sentry_event_level = logging.WARNING
if os.getenv('SENTRY_EVENT_LEVEL') == 'debug':
    sentry_event_level = logging.DEBUG
elif os.getenv('SENTRY_EVENT_LEVEL') == 'info':
    sentry_event_level = logging.INFO
elif os.getenv('SENTRY_EVENT_LEVEL') == 'warning':
    sentry_event_level = logging.WARNING
elif os.getenv('SENTRY_EVENT_LEVEL') == 'error':
    sentry_event_level = logging.ERROR
elif os.getenv('SENTRY_EVENT_LEVEL') == 'critical':
    sentry_event_level = logging.CRITICAL
sentry_sdk.init(
    dsn=os.getenv('SENTRY_DSN', ''),
    integrations=[
        LoggingIntegration(
            level=logging.DEBUG,            # Capture this level and above as breadcrumbs on events that occur
            event_level=sentry_event_level  # Send this level as events
        ),
    ],
)

# Logging setup
logger = logging.getLogger("texted")
level = os.getenv('LOGGING_LEVEL', 'debug')
if level == 'critical':
    logger.setLevel(logging.CRITICAL)
elif level == 'error':
    logger.setLevel(logging.ERROR)
elif level == 'warning':
    logger.setLevel(logging.WARNING)
elif level == 'info':
    logger.setLevel(logging.INFO)
else:
    level = 'debug'
    logger.setLevel(logging.DEBUG)


sh = logging.StreamHandler(stream=sys.stdout)
sh.setFormatter(logging.Formatter("[%(name)s] %(levelname)8s:  %(message)s"))
logger.addHandler(sh)
logger.info(f"Logging level set to {level}")

account_sid = os.environ["TWILIO_ACCOUNT_SID"]
auth_token = os.environ["TWILIO_AUTH_TOKEN"]
twilio_client = Client(account_sid, auth_token)


class CredentialsError(Exception):
    """Custom exception used whenever there is a problem with the Digital Ocean or Twilio credentials."""
    pass


def create_spaces_client():
    new_session = session.Session()
    # TODO: Add error handling here
    if os.getenv("DO_SPACES_KEY") is None or os.getenv('DO_SPACES_SECRET') is None:
        logger.error('Missing Digital Ocean Spaces Access Key or Secret...')
        raise CredentialsError("Missing Digital Ocean credentials")

    return new_session.client(
        "s3",
        region_name="nyc3",
        endpoint_url="https://nyc3.digitaloceanspaces.com",
        aws_access_key_id=os.getenv("DO_SPACES_KEY"),
        aws_secret_access_key=os.getenv("DO_SPACES_SECRET"),
    )


# File operations in Digital Ocean Spaces
# TODO: Handle error exceptions by notifying the user of an issue
def does_file_exist(filename):
    try:
        # NOTE: Cannot use 'head_object' here, even though we don't care about the file contents
        #   https://github.com/boto/boto3/issues/2442
        create_spaces_client().get_object(Bucket=os.getenv("DO_BUCKET_NAME"), Key=filename)
        return True
    except CredentialsError as ex:
        logger.warning("Credentials problem with Digital Ocean Spaces")
        return False
    except ClientError as ex:
        if ex.response['Error']['Code'] == 'NoSuchKey':
            logger.debug(f"Could not find {filename}")
        elif ex.response['Error']['Code'] == 'NoSuchBucket':
            logger.error(f"Bucket not found {os.getenv('DO_BUCKET_NAME')}")
            raise
        else:
            raise
        return False


def get_file_contents(filename):
    """
    Get the contents of a file from our bucket. The presence of that file indicates that the
    phone number has been seen by this system. The contents of the file indicate the timestamp of
    the last message received AFTER an opt-in. Before the opt-in has occurred, the file will be
    present but empty. If an opt-out occurs, the file contents are cleared to indicate this.

    :param filename: The filename to read, expected as `phone_number.txt`
    :return: None, if the file does not exist. Else, the contents of the file (should be a
        timestamp or an empty string)
    """
    try:
        query = create_spaces_client().get_object(Bucket=os.getenv("DO_BUCKET_NAME"), Key=filename)
        return query["Body"].read().decode("utf-8")
    except CredentialsError as ex:
        logger.warning("Credentials problem with Digital Ocean Spaces")
        raise
    except ClientError as ex:
        if ex.response['Error']['Code'] == 'NoSuchKey':
            logger.debug(f"Could not find {filename}")
        elif ex.response['Error']['Code'] == 'NoSuchBucket':
            logger.error(f"Bucket not found {os.getenv('DO_BUCKET_NAME')}")
            raise
        else:
            raise
        return None


def write_to_file(filename, content=""):
    try:
        # TODO
        create_spaces_client().put_object(Bucket=os.getenv("DO_BUCKET_NAME"), Key=filename, Body=content)
        return True
    except:  # noqa
        return False


def delete_file(filename):
    try:
        create_spaces_client().delete_object(Bucket=os.getenv("DO_BUCKET_NAME"), Key=filename)
        return True
    except:  # noqa
        return False


def send_message(message: dict) -> None:
    logger.debug(f"Sending message: {message}")

    # Prepare to call the Twilio api
    phone = message.get("phone")
    text = message["text"]
    stage = os.environ.get("STAGE", "dev")
    responses = get_responses()

    # Only send messages in production mode
    if stage == "prod":
        if message.get("media_url"):
            # sending a media message, which is just a text message with a media url
            tw_message = twilio_client.messages.create(
                body=text,
                from_=os.environ["TWILIO_ACCOUNT_PHONE_NUMBER"],
                to=phone,
                media_url=[message.get("media_url")],
            )
        else:
            tw_message = twilio_client.messages.create(
                body=text, from_=os.environ["TWILIO_ACCOUNT_PHONE_NUMBER"], to=phone
            )
        sid = tw_message.sid
        logger.info(f"Message sent: {sid}")

        # If this was the opt-in send a second reply with more welcoming instructions
        if text == responses["Greeting3"]["text"]:
            message = responses["Greeting4"]["text"]
            tw_message = twilio_client.messages.create(
                body=message, from_=os.environ["TWILIO_ACCOUNT_PHONE_NUMBER"], to=phone
            )
            sid = tw_message.sid
            logger.debug(f"Sending follow-up message: {message}")
            logger.info(f"Follow-up Message sent: {sid}")
    else:
        logger.info(f"Not calling Twilio API for response when in {stage}")

    return


# ====================================== main.py ================================


def keyword_ranker(text: str, responses: dict) -> dict:
    """text: the text to compare to the keywords
    responses: the responses.json file as a dictionary

    returns: a dictionary with the best match and the score
    """
    text = text.lower()
    best_match = {}
    base_keyword_list = list(responses.keys())
    keyword_and_score = {}

    base_keyword_list = [key for key in base_keyword_list if re.search(r"Greeting\d+", key) is None]
    logger.debug(f"Base list: {base_keyword_list}")

    # loop through the keywords and rank them
    for base_key in base_keyword_list:
        # Add the aliases to the list of keys to check
        # Skip any categories that don't define aliases (workflow / system messages)
        keys_to_check = responses.get(base_key, {}).get("aliases")
        if keys_to_check is None:
            continue
        og_key = base_key
        base_key = base_key.lower()
        keys_to_check.append(base_key)

        for key in keys_to_check:
            # score the keyword against the text
            # partial_ratio is more forgiving than ratio
            score = partial_ratio(key, text)
            keyword_and_score[key] = score
            if score > best_match.get("score", 0):
                best_match = {"score": score, "key": og_key}
            logger.debug(f"{og_key}[{key}]: {score}")

        # TODO not sure this logic is correct...
        ignore = responses.get(base_key, {}).get("ignore", [])
        if key in ignore:
            best_match = {"score": 0, "key": og_key}

    return best_match


def get_responses():
    # get responses.json file
    with open("responses.json", "r") as f:
        brain = json.load(f)
    return brain


def determine_message_type(phone: str) -> MessageType:
    """
    Determine what type of message this is from this number.  We have several message
    types defined as an Enum at the top of the code.

    * FIRST: The first time a number has ever communicated with the TextED line.
    * OPT_IN_MISSING: A subsequent message from a number that doesn't have a recorded
        opt-in for our system. This could also be a message from a number that has
        previously opted out.
    * RECENT_REPLY: A message that has been sent within RECENT_LIMIT_MINUTES of the last message.
    * LATER_REPLY: A message that comes more than RECENT_LIMIT_MINUTES after the previous message.

    returns: True if this is the first message from this phone number
    """
    # TODO check if the phone number is in the S3 bucket & get file contents
    filename = f"{phone}.txt"
    datetime_str = get_file_contents(filename)

    if datetime_str is None:
        return MessageType.FIRST
    elif datetime_str == "":
        return MessageType.OPT_IN_MISSING
    else:
        now = datetime.now()
        previous = datetime.strptime(datetime_str, DATETIME_FORMAT)
        min_diff = (now - previous).total_seconds() / 60.0

        if min_diff <= RECENT_LIMIT_MINUTES:
            return MessageType.RECENT_REPLY
        return MessageType.LATER_REPLY


def determine_is_first_message(phone: str) -> bool:
    """Determine if this is the first message from this phone number
    phone: the phone number to check

    returns: True if this is the first message from this phone number
    """
    # check if the phone number is in the database
    # remove the +1 from the phone number
    # TODO: Handle international numbers properly (cannot assume +1 prefix)
    phone = phone[1:]
    filename = f"{phone}.txt"
    return not does_file_exist(filename)


def mark_number_as_sent(phone: str) -> bool:
    """Mark the phone number as having sent a message
    phone: the phone number to mark

    returns: True if the phone number was marked
    """
    # check if the phone number is in the bucket
    filename = f"{phone}.txt"
    return write_to_file(filename)


def handle_first_message(message: dict) -> dict:
    # mark this phone number as having sent a message
    phone = message.get("phone")
    mark_number_as_sent(phone)

    # send the welcome message
    # FIXME: What if they opted in on message 1?
    first_message = get_responses()["Greeting1"]["text"]

    logger.debug(f"Sending message: {first_message}")
    outgoing_message = {"phone": phone, "text": first_message}

    return outgoing_message


def handle_missing_opt_in(message: dict) -> dict:
    phone = message.get("phone")
    text = message.get("text")
    # Check if this is an opt-in
    # FIXME: multiple opt-in keyword support
    if text.lower() == "start":
        write_to_file(f"{phone}.txt", datetime.now().strftime(DATETIME_FORMAT))
        return {"phone": phone, "text": get_responses()["Greeting3"]["text"]}
    else:
        # ask for an opt-in again
        return {"phone": phone, "text": get_responses()["Greeting2"]["text"]}


def handle_reset(message: dict) -> dict:
    # figure the filename
    phone = message.get("phone")
    filename = f"{phone}.txt"
    delete_file(filename)

    # send the reset message
    outgoing_message = {"phone": message.get("phone"), "text": "Reset successful"}

    return outgoing_message


def handle_message(message: dict) -> dict:
    # TODO: Create a Spaces client once -- pass down to function

    # Identify the phone number to text back
    logger.debug(f"Handling message: {message}")
    phone = message.get("phone")
    # determine the MessageType to determine how to handle the message
    message_type = determine_message_type(phone)
    logger.debug(f"Message Type: {message_type}")

    if message_type == MessageType.FIRST:
        logger.info(f"This is our first message from: {phone}")
        return handle_first_message(message)
    elif message_type == MessageType.OPT_IN_MISSING:
        logger.info(f"Subsequent message from {phone} but no opt-in on record")
        return handle_missing_opt_in(message)

    text = message.get("text")

    # handle the reset message
    # TODO -- change this to the opt-out keywords defined in the Twilio Console
    if text.lower() == "reset":
        # delete the file for this phone number
        return handle_reset(message)

    # create the outgoing message dictionary for send_message to use later
    outgoing_message = {"phone": phone, "text": None}

    responses = get_responses()
    # Set up the help message (all response headers minus the greetings)
    responses = {key: value for key, value in responses.items() if re.search(r"Greeting\d+", key) is None}
    help_text = "".join(
        [f"\n{key}" for key, item in responses.items()]
    )

    # Check if the user is asking for help
    if text.lower() == "help" or text.lower() == "keywords":
        outgoing_message["text"] = (
            "The following keywords can be used to find resources:\n\n" + help_text
        )
        return outgoing_message

    # Rank the message against our keywords with the fuzzy matching logic
    # NOTE: This could be improved, and we know it. First edition of textED
    #   will be released with this logic, but we might move to a decision tree
    #   or even more natural language support using ChatGPT APIs (if funded)
    ranked_keyword = keyword_ranker(text, responses)
    logger.debug(f"ranked keyword: {ranked_keyword}")
    if ranked_keyword.get("score", 0) < MATCH_MISSING_THRESHOLD:
        # If the score is less than our MATCH_MISSING_THRESHOLD, no good matches exists
        keyword_help_text = (f"I'm not sure what you are asking about.\n\n" +
                             f"Try asking about one of the following topics: {help_text}")
        outgoing_message["text"] = keyword_help_text
    else:
        # We found a match above threshold
        matched_keyword = ranked_keyword.get("key")

        response = responses[matched_keyword]
        text_response = response.get("text")
        image_response = response.get("image_url")

        # If the score is less than our MATCH_UNCERTAIN_THRESHOLD, give them extra help
        if ranked_keyword.get("score") < MATCH_UNCERTAIN_THRESHOLD:
            text_response += "\n\n\nNot what you were looking for? Text \"keywords\" or \"help\" for options."

        if text_response:
            outgoing_message["text"] = text_response
        if image_response:
            outgoing_message["media_url"] = [image_response]

    return outgoing_message


def validate_responses_file():
    # get responses.json file
    with open("responses.json", "r") as f:
        brain = json.load(f)

    # loop through the keywords and rank them
    errors = []
    for key, value in brain.items():
        key = key.lower()
        # make sure the key is a string
        if not isinstance(key, str):
            errors.append(f"Invalid key, must be string: {key}")
        # test is required
        if not value.get("text"):
            errors.append(f"Missing text for {key}")
        # not required, but if it exists, it must be a list
        if value.get("aliases"):
            if not isinstance(value.get("aliases"), list):
                errors.append(f"Invalid aliases for key: {key}")

                # make sure each alias is a string
                for alias in value.get("aliases"):
                    if not isinstance(alias, str):
                        errors.append(f"Invalid alias for key: {key}, Alias: {alias}")
        if value.get("image_url"):
            scheme = None
            try:
                scheme = urlparse(value.get("image_url")).scheme

                if scheme not in ["http", "https"]:
                    errors.append(f"Invalid image_url for key: {key}")
            except Exception:
                errors.append(f"Invalid image_url for key: {key}")

    if len(errors) > 0:
        error_str = "\n".join(errors)
        raise Exception(f"Invalid responses.json file. Errors:\n {error_str}")

    logger.debug("The 'responses.json' file is valid")


def main(event):
    """Main function

    This function is expected for the Digital Ocean Serverless functions execution.
    By default, the main function is called with two parameters (event and context)

    See official documentation here: https://docs.digitalocean.com/products/functions/reference/runtimes/python/
    """
    from_phone = event.get("From")
    optin_phone = event.get("phone")
    message = event.get("Body")

    # Error handling (need a phone, message can be empty -- not None)
    # TODO: use a best practice phone number regex here
    message = "" if message is None else message
    if event.get("notsosecret") == 'texted-optin-webform':
        # Handle an opt-in through the website form
        logger.info(f"Received a website opt-in request from phone: {optin_phone}")
    elif from_phone is None:
        logger.warning(f"Cannot process incoming events without a 'From' phone: {from_phone}")
        return {"statusCode": 400, "body": "Cannot process incoming events without a 'From' phone"}

    logger.info(f"Received event. From: {from_phone}, Message: {message}")
    logger.debug(f"Complete event details:  {event}")

    incoming_message = {"phone": from_phone, "text": message}

    try:
        reply_msg = handle_message(incoming_message)
        send_message(reply_msg)
    except Exception as e:
        logger.error(f"Internal server error: {e.__str__()}")
        return {"statusCode": 500, "body": e.__str__()}

    return {"statusCode": 200, "body": "Successful execution"}





def simulate():
    parser = argparse.ArgumentParser(description="Execute a simulated call to the textED system")
    parser.add_argument("-w", "--webform", action="store_true")
    parser.add_argument("-m", "--message", nargs="?", default=None)
    parser.add_argument("-p", "--phone", nargs="?")
    args = parser.parse_args()
    print(f"{args} HERE")

    if args.phone is None:
        print("\n\nA 'phone' is required for command line execution...\n")
        sys.exit(-1)
    elif args.webform and (args.message is not None):
        print("\n\nYou cannot set a text message body for the webform opt-in execution...\n")
        sys.exit(-2)

    # Proper CLI arguments, continue simulation
    msg = {}
    if args.webform:
        msg = {
            "From": args.phone,
            "notsosecret": "texted-optin-webform"
        }
    else:
        msg = {
            "From": args.phone,
            "Body": args.message
        }
    main(msg)


"""Command line execution"""
if __name__ == "__main__":
    simulate()

