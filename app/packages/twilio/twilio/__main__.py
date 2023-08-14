import json
from urllib.parse import urlparse
from twilio.rest import Client
from rapidfuzz.fuzz import partial_ratio

from boto3 import session
import os
import logging
from dotenv import load_dotenv
import datetime

logging = logging.getLogger(__name__)

load_dotenv()
account_sid = os.environ["TWILIO_ACCOUNT_SID"]
auth_token = os.environ["TWILIO_AUTH_TOKEN"]
client = Client(account_sid, auth_token)

# ========================== Analytics ==========================
# NOTE: I don't know if this is wanted, so its disabled, but I thought it would be cool.
ENABLE_ANALYTICS = False
ADMIN_PHONE_NUMBERS = ["+13192406893"]  # jed's phone number


def create_spaces_client():
    new_session = session.Session()
    return new_session.client(
        "s3",
        region_name="nyc3",
        endpoint_url="https://nyc3.digitaloceanspaces.com",
        aws_access_key_id=os.getenv("DO_SPACES_KEY"),
        aws_secret_access_key=os.getenv("DO_SPACES_SECRET"),
    )


# File operations in Digital Ocean Spaces
def does_file_exist(filename):
    try:
        create_spaces_client().head_object(Bucket="edci-texts", Key=filename)
        return True
    except: # noqa
        return False


def get_file_contents(filename):
    try:
        response = create_spaces_client().get_object(Bucket="edci-texts", Key=filename)
        return response["Body"].read().decode("utf-8")
    except: # noqa
        return None


def create_new_file(filename, content=""):
    try:
        create_spaces_client().put_object(
            Bucket="edci-texts", Key=filename, Body=content
        )
        return True
    except: # noqa
        return False


def delete_file(filename):
    try:
        create_spaces_client().delete_object(Bucket="edci-texts", Key=filename)
        return True
    except: # noqa
        return False


# ====================================== twilio/utils.py ================================
# Twilio is all the text messaging stuff


def send_message(message: dict) -> str:
    # call the twillo api
    phone = message.get("phone")
    text = message["text"]
    # dont actual send a message if we are developing locally
    stage = os.environ.get("STAGE", "dev")
    print(message)
    if stage == "prod":
        if message.get("media_url"):
            # sending a media message, which is just a text message with a media url
            tw_message = client.messages.create(
                body=text,
                from_=os.environ["TWILIO_ACCOUNT_PHONE_NUMBER"],
                to=phone,
                media_url=message.get("media_url"),
            )
        else:
            tw_message = client.messages.create(
                body=text, from_=os.environ["TWILIO_ACCOUNT_PHONE_NUMBER"], to=phone
            )
        sid = tw_message.sid
        print(f"message sent: {sid}")

    return message


# ====================================== main.py ================================


def keyword_ranker(text: str, responses: dict) -> dict:
    """text: the text to compare to the keywords
    responses: the responses.json file as a dictionary

    returns: a dictionary with the best match and the score
    """
    text = text.lower()
    best_match = {}
    base_keyword_list = list(responses.keys())
    base_key = None
    keyword_and_score = {}
    keys_to_ignore = []  # keys to ignore if they are in the text

    base_keyword_list = [key for key in base_keyword_list if key not in keys_to_ignore]

    # loop through the keywords and rank them
    for base_key in base_keyword_list:
        # add the aliases to the list of keys to check
        keys_to_check = responses.get(base_key, {}).get("aliases", [])
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

        ignore = responses.get(base_key, {}).get("ignore", [])
        if key in ignore:
            best_match = {"score": 0, "key": og_key}

    return best_match


def get_responses():
    # get responses.json file
    with open("responses.json", "r") as f:
        brain = json.load(f)
    return brain


def determine_is_first_message(phone: str) -> bool:
    """Determine if this is the first message from this phone number
    phone: the phone number to check

    returns: True if this is the first message from this phone number
    """
    # check if the phone number is in the database
    # remove the +1 from the phone number
    phone = phone[1:]
    filename = f"{phone}.txt"
    return not does_file_exist(filename)


def mark_number_as_sent(phone: str) -> bool:
    """Mark the phone number as having sent a message
    phone: the phone number to mark

    returns: True if the phone number was marked
    """
    # check if the phone number is in the database
    # remove the +1 from the phone number
    phone = phone[1:]
    filename = f"{phone}.txt"
    return create_new_file(filename)


def handle_first_message(message: dict) -> dict:
    # mark this phone number as having sent a message
    phone = message.get("phone")
    mark_number_as_sent(phone)
    # send the welcome message

    first_message = "Thanks for messaging TextED! The following keywords can be used to find resources: "

    responses = get_responses()
    # ignore the greeting
    ingore_keys = ["Greeting"]
    responses = {
        key: value for key, value in responses.items() if key not in ingore_keys
    }
    first_message += "".join(
        [f"\n{key} -  {item['text']}" for key, item in responses.items()]
    )

    outgoing_message = {"phone": phone, "text": first_message}

    return outgoing_message


def handle_reset(message: dict) -> dict:
    # figure the filename
    phone = message.get("phone")
    phone = phone[1:]
    filename = f"{phone}.txt"
    delete_file(filename)

    # send the reset message
    outgoing_message = {"phone": message.get("phone"), "text": "Reset successful"}

    return outgoing_message


def handle_get_analytics(message: dict) -> dict:
    # make sure the user is an admin
    phone = message.get("phone")

    if phone not in ADMIN_PHONE_NUMBERS:
        return {"phone": message.get("phone"), "text": "Error"}

    # get the analytics
    analytics = get_file_contents("keyword_analytics.json")

    # make an easy to read version
    analytics = json.loads(analytics)
    pretty_string = "Analytics \n"
    updated_at = None
    created_at = None
    key_value_string = ""
    for key, value in analytics.items():
        if key == "last_updated":
            updated_at = value
            continue
        elif key == "created_at":
            created_at = value
            continue
        else:
            key_value_string += f"{key}: {value}\n"

    pretty_string += f"Since: {created_at}\n"
    pretty_string += f"Latest: {updated_at}\n\n\n"

    pretty_string += key_value_string

    return {"phone": message.get("phone"), "text": pretty_string}


def log_keyword_usage(keyword: str) -> None:
    """Log the keyword usage

    keyword: the keyword that was used

    returns: None

    This just increments the keyword usage in the keyword_analytics.json file.
    It might slow down the response time.
    """

    # get the latest value
    # if the analytics file doesnt exist, create it
    analyics_filename = "keyword_analytics.json"

    try:
        if not does_file_exist(analyics_filename):
            new_file = {
                "created_at": datetime.datetime.utcnow().isoformat(),
            }
            create_new_file(analyics_filename, json.dumps(new_file, indent=4))

        current_analytics = get_file_contents(analyics_filename)
        current_analytics = json.loads(current_analytics)

        # increment the value
        current_analytics[keyword] = current_analytics.get(keyword, 0) + 1
        # update the last updated time
        current_analytics["last_updated"] = datetime.datetime.utcnow().isoformat()

        # write the new value
        create_new_file(analyics_filename, json.dumps(current_analytics, indent=4))
    except Exception as e:
        print("error logging keyword usage: ", e)


def handle_message(message: dict) -> str:
    # identify the phone number to text back
    print("handling message : ", message)
    phone = message.get("phone")
    # determine which function to call based on message text
    is_first_message = determine_is_first_message(phone)

    if is_first_message:
        return handle_first_message(message)

    text = message.get("text")

    # handle the reset message
    if text.lower() == "reset":
        # delete the file for this phone number
        return handle_reset(message)

    # handle the analytics message
    if text.lower() == "analytics":
        return handle_get_analytics(message)

    # create the outgoing message dictionary for send_message to use later
    outgoing_message = {"phone": phone, "text": None}

    responses = get_responses()
    # ignore the greeting
    responses = {key: value for key, value in responses.items() if key != "Greeting"}
    help_text = "".join(
        [f"\n{key} -  {item['text']}" for key, item in responses.items()]
    )
    # first, check if the user is asking for help
    # TODO: Something with Twilio intercepts the help message and sends a stop message to the user.
    # Check the configuration for this number.
    if text.lower() == "help":
        outgoing_message["text"] = (
            "The following keywords can be used to find resources: " + help_text
        )
        return outgoing_message

    ranked_keyword = keyword_ranker(text, responses)
    print("ranked keyword: ", ranked_keyword)
    # if the score is less than .5, then the keyword is not recognized
    if ranked_keyword.get("score", 0) <= 0.5:
        keyword_help_text = (
            f"Not recongized. Try using one of the following: {help_text}"
        )
        outgoing_message["text"] = keyword_help_text

        # log the keyword usage if enabled
        if ENABLE_ANALYTICS:
            log_keyword_usage("Not recognized")
    else:
        matched_keyword = ranked_keyword.get("key")

        # log the keyword usage if enabled
        if ENABLE_ANALYTICS:
            log_keyword_usage(matched_keyword)

        response = responses[matched_keyword]
        text_response = response.get("text")
        image_response = response.get("image_url")

        if ranked_keyword.get("score") < 70:
            text_response += '\nNot what you\'re looking for? Text "keywords" for help.'

        if text_response:
            outgoing_message["text"] = text_response
        if image_response:
            outgoing_message["media_url"] = image_response

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
            errors.append((f"Invalid key, must be string: {key}"))
        # test is required
        if not value.get("text"):
            errors.append((f"Missing text for {key}"))
        # not required, but if it exists, it must be a list
        if value.get("aliases"):
            if not isinstance(value.get("aliases"), list):
                errors.append((f"Invalid aliases for key: {key}"))

                # make sure each alias is a string
                for alias in value.get("aliases"):
                    if not isinstance(alias, str):
                        errors.append((f"Invalid alias for key: {key}, Alias: {alias}"))
        if value.get("image_url"):
            scheme = None
            try:
                scheme = urlparse(value.get("image_url")).scheme

                if scheme not in ["http", "https"]:
                    errors.append((f"Invalid image_url for key: {key}"))
            except Exception:
                errors.append((f"Invalid image_url for key: {key}"))

    if len(errors) > 0:

        error_str = "\n".join(errors)
        raise Exception(f"Invalid responses.json file. Errors:\n {error_str}")

    print("responses.json file is valid")


def main(args):
    from_phone = args.get("From")
    message = args.get("Body")

    logging.info(f"from: {from_phone}, message: {message}")

    incoming_message = {"phone": from_phone, "text": message}
    try:
        reply_msg = handle_message(incoming_message)
        send_message(reply_msg)
    except Exception as e:
        print("error: ", e.__str__())
        return {"statusCode": 500, "body": e.__str__()}

    return {"statusCode": 200, "body": "Hey"}


if __name__ == "__main__":
    import sys

    args = sys.argv
    msg = {
        "From": "+13192406893",
        "Body": args[1] if len(args) > 1 else "help",
    }
    main(msg)
