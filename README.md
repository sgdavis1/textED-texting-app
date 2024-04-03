# textED-Resources

## Stack

- Python 3.9
- [Digital Ocean Functions](https://docs.digitalocean.com/products/functions/)
- [Twilio](https://www.twilio.com/docs/sms)
- [Digital Ocean Spaces](https://docs.digitalocean.com/products/spaces/)

## How to run locally

First setup

```bash
git clone git@github.com:sgdavis1/textED-texting-app.git
cd ./textED-texting-app
# create a virtual environment
python -m venv venv
# install requirements
# NOTE: you need to keep this up to date with the requirements.txt in the function directory or just use that
source venv/bin/activate
pip install -r ./app/packages/edciowa/texted/requirements.txt
cp env-example ./app/packages/edciowa/texted/.env
```

### Configuring the environment

The `.env` requires several valid settings to enable local execution

* Twilio Account credentials
* Digital Ocean credentials

#### Twilio account credentials

Twilio will require an **Auth token** and a valid sender **phone number**. These can be created from the
Twilio console available here: https://console.twilio.com/

_Note:_ The current application uses the older authentication style "Auth token". In the future, 
this should be updated to use the preferred and more secure "API key" method.

#### Digital Ocean account credentials

After creating a Digital Ocean account you will need to create a **Spaces Key** and  **Secret**. 
These can be created from the DO console here: https://cloud.digitalocean.com/

Your account will need an existing bucket with the name defined in your `.env` settings.

### Sentry credentials

You will need to set up a Sentry project to collect logs: https://sentry.io/

### Running the app

Inside the `/app/packages/edciowa/texted/` directory

```bash
python __main__.py "Your message here"
```

## How to deploy

_NOTE_: you'll need the Digital Ocean CLI tool [installed and configured](https://docs.digitalocean.com/reference/doctl/how-to/install/).
  Remember to create a valid functions Namespace as well.

### Preferred: Script

Simply run the supplied deployment script:

```bash
./deploy.sh
```

### Alternative: Manual deployment

Before deployment, make sure that all of the required environment variables are set in your
current shell, or the deployment will fail with `Error: The following substitutions could not be resolved:`

```bash
set -a
source app/package/edciowa/texted/.env
set +a
```

Deploy with the `doctl` tool:

```bash
doctl serverless deploy app
```

### Testing deployed function

Once deployed, there are several methods of testing the function. It is a good idea to first change
the deployed `STAGE` of the function to `dev` so that Twilio API calls are not made during your 
testing, unless this is desired.

#### Using The Digital Ocean Console

Navigate through the console to the function that was just deployed. There is a section to 
adjust the incoming parameters, you will need to set a valid JSON body with the properties `From` and `Body`
in order to get the function to execute properly. These values are retained in the console but do not affect
external Web / REST calls.

#### Using `curl`

You can use a curl call from any system with an internet connection that should execute the function
and return the response 'Successful execution' with a response code of 200.

The specific syntax for the call is documented in the Functions console as a `GET` request, but you will
need to use a `POST` request with  in order to pass a valid body of a JSON object containing the `From` 
and `Body` parameters.

Example:
```bash
curl -X POST "FUNCTION_URL_FROM_DIGITAL_OCEAN_CONSOLE" \
  -H "Content-Type: application/json" -d '{"From": "15555555555", "Body": "Hello"}'
```

## General Notes

### Is there testing?

No, not really. Previous developer was just lazy.

### Are there analytics?

There's a very rudimentary analytics system in place. It checks the `keyword_analytics.json` in the bucket to see. Basically, it increments a counter for each keyword and writes it to a file. If the service is very busy, I would expect some missing some but, it's better than nothing. You can also view the logs in the Digital Ocean and Twilio dashboards.

Digital ocean functions require a `__main__.py` file in the root of the function directory. You can read about it [here](https://docs.digitalocean.com/products/functions/), ultimately it was much easier to put everything in 1 file. I thought Python was a good language choice because it's easy to read and write, and it's a language that I'm familiar with. Plus there's a few libraries that make it easy to do simple NLP things. I tried to leave helpful comments in the code, please reach out if you have any questions at <jedrmeier@gmail.com>, I'm always happy to help.

### Why does it need to use Digital Ocean Spaces?

To persist the user state. We just store a the phone number as an empty text file instead of putting it in a database. Its cheaper and more simple than using a database and its only written 1 time.

### How does the keyword matching work?

To extract the "intent" or "keyword", we really just do a fuzzy match. This is the library I used: [rapidfuzz](https://pypi.org/project/rapidfuzz/). It simple and fast, but doesn't work beyond simple matching. We are just trying to handle the edge cases where people don't send exactly the right keywords, kind of like an autocorrect. See the [main](/app/packages/edciowa/texted/__main__.py#L106) for more details.

### How do I add/edit/remove responses?

Edit the `responses.json` in the function directory. It maps keywords to responses. Keywords are case insensitive, ensure unique keywords. To add a new keyword, add a new key to the json object. To edit a response, edit the value of the keyword. To remove a response, remove the key from the json object. There is a `validate_responses_file()` function inside of the __main__.py. You can run it locally to validate the file. It will throw an error with details if there is a problem.

Example:

```python
{
    "Weight Neutral Card": { # the main keyword
        "text": "Weight Neutral Card", # required, the text that will be sent back to the user
        "aliases":["weight card","weight neutral card"], # optional, any other keywords that should map to this response
        "image_url":"https://www.edciowa.com/_files/ugd/93ebaa_2d33bb227e1647babc56659c5fc9105a.pdf" # optional, an image url to send back to the user
    }
}
```

Example:

```python
{
    "created_at": "2023-08-14T17:57:22.012114",
    "last_updated": "2023-08-14T17:59:32.120019",
    "Weight Neutral Card": 4
    # ... more keywords and their counts
}
```

## Current Production credentials

Currently, production credentials are associated with the following accounts:

| Service       | email                 | 2FA |
|---------------|-----------------------| --- |
| Twilio        | treasurer@edciowa.org | Yes (TOTP) |
| Digital Ocean | sgdavis1@gmail.com    | OAuth via Github |
| Sentry        | sgdavis@bioneos.com   | OAuth via Github |
