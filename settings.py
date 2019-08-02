# -*- coding: utf-8 -*-
# settings
import os

# time expire
EXPIRE_MINUTES = 720

# Skype credentials
SKY_USERNAME = ''
SKY_PASSWORD = ''

SKY_USERNAME_NICK = ''

# Slack data
SLACK_WEBHOOK = ''
SLACK_BOT_USERNAME = 'Skype Bot'
SLACK_CHANNEL = ''
SLACK_CHANNEL_PERSONAL = ''
SLACK_BOT_ICON = 'https://store-images.s-microsoft.com/image/apps.21258.9007199266245651.2c55aa37-6559-4c49-aa18-f0c' \
				 'a327494b9.f1b2b679-3b9c-423c-b395-4ea6ec3a9807?mode=scale&q=90&h=270&w=270&background=%230078D4'


# MSG for auto reply
bot_msg = '(captainphasma) This message was generate automatically - sky-bot-edw. \n  (truck) sending to Slack. .. .'
SKY_MSG_RESPONSE = 'hi @user , {}'.format(bot_msg)

SKY_MSG_RESPONSE_AT = '@user sorry, I am a bot :/'

# dict for wrapper slack channels with skype ids
SKYPE_SLACK_WRAPPER = {}

try:
	from local_settings import *
except ImportError:
	print('not local settings')
