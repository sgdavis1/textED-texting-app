# textED-Resources

## Stack

- Python 3.9
- [Digital Ocean Functions](https://docs.digitalocean.com/products/functions/)
- [Twilio](https://www.twilio.com/docs/sms)
- [Digital Ocean Spaces](https://docs.digitalocean.com/products/spaces/)

## How to run locally

First setup

```bash
git clone git@github.com:jrmeier/textED-texting-app.git
cd ./textED-texting-app
# create a virtual environment
python -m venv .texted_texting_app
# install requirements
# NOTE: you need to keep this up to date with the requirements.txt in the function directory or just use that
source .texted_texting_app/bin/activate
pip install -r ./app/packages/twilio/twilio/requirements.txt
copy .env.example .app/packages/twilio/twilio/.env
cd ./app/packages/twilio/twilio
```

### Running the app

Inside of the `/app/packages/twilio/twilio` directory

```bash
python __main__.py "Your message here"
```

### How to deploy

Note: you'll need the docker cli installed and configured. You can install it via `brew install doctl` on Mac.

```bash
doctl serverless deploy app  --remote-build
```

### Is there testing?

No, not really. I'm just lazy.

### Are there analytics?

There's a very rudimentary analytics system in place. It checks the `keyword_analytics.json` in the bucket to see. Basically, it increments a counter for each keyword and writes it to a file. If the service is very busy, I would expect some missing some but, it's better than nothing. You can also view the logs in the Digital Ocean and Twilio dashboards.

Digital ocean functions require a `__main__.py` file in the root of the function directory. You can read about it [here](https://docs.digitalocean.com/products/functions/), ultimately it was much easier to put everything in 1 file. I thought Python was a good language choice because it's easy to read and write, and it's a language that I'm familiar with. Plus there's a few libraries that make it easy to do simple NLP things. I tried to leave helpful comments in the code, please reach out if you have any questions at <jedrmeier@gmail.com>, I'm always happy to help.

### Why does it need to use Digital Ocean Spaces?

To persist the user state. We just store a the phone number as an empty text file instead of putting it in a database. Its cheaper and more simple than using a database and its only written 1 time.

### How does the keyword matching work?

To extract the "intent" or "keyword", we really just do a fuzzy match. This is the library I used: [rapidfuzz](https://pypi.org/project/rapidfuzz/). It simple and fast, but doesn't work beyond simple matching. We are just trying to handle the edge cases where people don't send exactly the right keywords, kind of like an autocorrect. See the [main](/app/packages/twilio/twilio/__main__.py#L106) for more details.

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
