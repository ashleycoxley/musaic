'''
This function handles a Slack slash command and echoes the details back to the user.

Follow these steps to configure the slash command in Slack:

  1. Navigate to https://<your-team-domain>.slack.com/services/new

  2. Search for and select "Slash Commands".

  3. Enter a name for your command and click "Add Slash Command Integration".

  4. Copy the token string from the integration settings and use it in the next section.

  5. After you complete this blueprint, enter the provided API endpoint URL in the URL field.


To encrypt your secrets use the following steps:

  1. Create or use an existing KMS Key - http://docs.aws.amazon.com/kms/latest/developerguide/create-keys.html

  2. Click the "Enable Encryption Helpers" checkbox

  3. Paste <COMMAND_TOKEN> into the kmsEncryptedToken environment variable and click encrypt


Follow these steps to complete the configuration of your command API endpoint

  1. When completing the blueprint configuration select "Open" for security
     on the "Configure triggers" page.

  2. Enter a name for your execution role in the "Role name" field.
     Your function's execution role needs kms:Decrypt permissions. We have
     pre-selected the "KMS decryption permissions" policy template that will
     automatically add these permissions.

  3. Update the URL for your Slack slash command with the invocation URL for the
     created API resource in the prod stage.
'''

import boto3
import json
import logging
import os
import requests
import slackclient
import spotipy
import spotipy.util as util
import json
import re
import os
import random
import string

from base64 import b64decode
from urlparse import parse_qs


ENCRYPTED_EXPECTED_TOKEN = os.environ['kmsEncryptedToken']

kms = boto3.client('kms')
expected_token = kms.decrypt(CiphertextBlob=b64decode(ENCRYPTED_EXPECTED_TOKEN))['Plaintext']
slackToken = os.environ['SLACK_TOKEN']

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def respond(err, res=None):
    return {
        'statusCode': '400' if err else '200',
        'body': err.message if err else json.dumps(res),
        'headers': {
            'Content-Type': 'application/json',
        },
    }


def lambda_handler(event, context):
        
    logger.info("Request event %s", event)

    apiUrl = "https://slack.com/api/channels.history"
    musicChannel = "C1TKE41RA"
    payload = {'token': slackToken, 'channel': musicChannel}
            
    data = requests.get(apiUrl, params=payload).json()
    
    for message in data['messages']:
        text = message.get('text')
        if "spotify" in text:
            logger.info("Spotify results %s", text)
            
    #challenge = json.loads(event['body'])['challenge']
    #if challenge:
    #  logger.info("Challenge = %s", challenge)
    #  return respond(None, challenge)

    PARAM_NAMES = ["SPOTIFY_CLIENT_ID", "SPOTIFY_CLIENT_SECRET"]
    auth_params = get_auth_params(PARAM_NAMES)
    MOSAIC_USERNAME = "2rdfnhmheub8zbpuklaypzldo"
    #TOKEN = authorize_spotify(MOSAIC_USERNAME, auth_params)
    TOKEN = "BQD-X5MnCDLibVAY_PiwHnD0YYe3DSC_d3ZTGQ0B4Y7qZjVnfqcl62FXv1nkdAe7X7wbKONf5wftatdY_HxCTupoQoo8k8Ndw4bNCAdK9dZ3tLbgC5VCV1stceah3aabQMg-t3TO3vcbKL2V2KJFZMDJMO3jg6_M3MTvqTTmphY6QCXIw7LbbcxE3XKEK0lc82HBv-Inp7-F3-evZlWF0x9vAoojXAk"

    spotify = initialize_spotify(TOKEN)
   
    playlist_id = generate_playlist(data, MOSAIC_USERNAME, spotify)

    playlist_url = "https://open.spotify.com/user/2rdfnhmheub8zbpuklaypzldo/playlist/" + playlist_id
    params = parse_qs(event['body'])

    token = params['token'][0]

    if token != expected_token:
        logger.error("Request token (%s) does not match expected", token)
        return respond(Exception('Invalid request token'))

    user = params['user_name'][0]
    command = params['command'][0]
    channel = params['channel_name'][0]
    #command_text = params['text'][0]

    return respond(None, "Generated this playlist for %s: %s" % (user, playlist_url))

def get_auth_params(param_names):
    """Get authorization parameters from environment variables for a list of auth param names"""
    def get_auth_param(name):
        param = os.environ.get(name)
        if param:
            return param
        else:
            return ""

    auth_params = {}
    for name in param_names:
        auth_params[name] = get_auth_param(name)

    return auth_params


def authorize_spotify(user_id, auth_params):
    return util.prompt_for_user_token(
        user_id,
        "playlist-modify-public",
        client_id = auth_params['SPOTIFY_CLIENT_ID'],
        client_secret = auth_params['SPOTIFY_CLIENT_SECRET'],
        redirect_uri = 'http://ashleycoxley.com'
        )


def parse_spotify_track_id(message):
    search = re.search(r"(spotify)(\.com/|:)(track)(/|:)(\w+)", message)
    if search:
        return search.groups()[4]


def initialize_spotify(token):
    return spotipy.Spotify(auth=token)


def generate_playlist(slack_message_json, username, spotify):
    track_id_list = []
    for message in slack_message_json['messages']:
        track_id = parse_spotify_track_id(message['text'])
        if track_id:
            track_id_list.append(track_id)
    
    playlist_id = spotify.user_playlist_create(username, random_playlist_name())['id']

    spotify.user_playlist_add_tracks(username, playlist_id, track_id_list)
    return playlist_id


def random_playlist_name():
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(6))
