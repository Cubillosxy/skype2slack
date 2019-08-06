# -*- coding: utf-8 -*-
import datetime
import re
import shutil
import subprocess
import sys
import os
import traceback

import logzero
import requests
from logzero import logger
from skpy import SkypeEventLoop
from skpy import SkypeNewMessageEvent

from settings import SKYPE_SLACK_WRAPPER
from settings import SKY_MSG_RESPONSE
from settings import SKY_PASSWORD, SKY_MSG_RESPONSE_AT, EXPIRE_MINUTES, SLACK_CHANNEL_PERSONAL, SKY_USERNAME_NICK
from settings import SKY_USERNAME
from settings import SLACK_BOT_ICON
from settings import SLACK_BOT_USERNAME
from settings import SLACK_CHANNEL
from settings import SLACK_WEBHOOK


class SkypePing(SkypeEventLoop):
	_ids_reg = {}

	def __init__(self, username, password):
		# Setup rotating logfile with 3 rotations, each with a maximum filesize of 1MB:
		self.log_filename = 'skype_log.log'
		self.log_path = '/tmp/{}'.format(self.log_filename)
		self.username = username
		self.password = password
		logzero.logfile(self.log_path, maxBytes=1e6, backupCount=3)

	def start(self):
		self.write_log('sending credentials')
		super(SkypePing, self).__init__(self.username, self.password)
		self.write_log('connect ok')
		self.loop()

	@staticmethod
	def check_regex(content):
		username_regex = '{}.'.format(SKY_USERNAME)
		result_2 = False

		result_1 = re.search(username_regex, content)
		if SKY_USERNAME_NICK:
			nick_regex = '>{}<'.format(SKY_USERNAME_NICK)
			result_2 = re.search(nick_regex, content)
		return result_1 or result_2

	@staticmethod
	def write_log(content, level='info'):
		try:
			getattr(logger, level)(content.encode('utf-8'))
		except:
			logger.error('error trying to write, "{}"'.format(level))

	@staticmethod
	def format_at_msg(content):
		content = re.sub(r'<at.id="[a-zA-Z0-9_:\*\. \-]+">', '*@', content)
		content = re.sub(r'</at>', '*', content)
		return content

	def format_msg_slack(self, content):

		quote_msg = re.findall(r'</legacyquote>(.*)<legacyquote>', content)
		quote_msg_2 = re.findall(r'<legacyquote>(.*)</legacyquote>', content)
		if quote_msg or quote_msg_2:
			author = re.findall(r'authorname="([a-zA-Z \-_0-9\.,]+)"', content)[0]
			timestamp = float(re.findall(r'timestamp="([0-9 ]+)"', content)[0])
			time_format = datetime.datetime.fromtimestamp(timestamp).strftime('%Y/%m/%d at %I:%M %p')
			complement = re.findall(r'</quote>(.*)', content)[0]
			complement = self.format_at_msg(complement)
			quote = self.format_at_msg(quote_msg[0])

			# remove extend text
			quote = re.sub(
				r'<e_m a="[a-zA-Z0-9_:\*\. \-]+".[a-zA-Z0-9_="]+.[a-zA-Z0-9_="]+.[a-zA-Z0-9_="]+></e_m>',
				'',
				quote
			)

			text_quote = '>>> _{quote}_ \n `{author}, {time_format}` \n {complement}'.format(
				quote=quote,
				author=author,
				time_format=time_format,
				complement=complement,
			)

		else:
			text_quote = self.format_at_msg(content)

		# change link format
		text_quote = re.sub(r'<a|href="|">(https?://)?[a-z\.0-9/_-]+</a>', '', text_quote)

		# remove skype emojis :
		text_quote = re.sub(r'<ss.[a-z=">\(]+\)</ss>', '~emoji~', text_quote)

		# format <b>  msg
		text_quote = re.sub(r'<b raw_pre="\*" raw_post="\*">|</b>', '*', text_quote)

		# format <i> _ msg
		text_quote = re.sub(r'<i raw_pre="_" raw_post="_">|</i>', '_', text_quote)

		# TODO: replace skype emojis for slack
		return text_quote

	def ram_memory(self, sub, msg_id, rw_type):
		'''
		:param sub: nick
		:param msg_id: skype message id
		:param rw_type: response type
		:return: True, if was add
		'''
		user = self._ids_reg.get(sub)
		is_new = False
		now = datetime.datetime.utcnow()
		if not user:
			self._ids_reg[sub] = {rw_type: [msg_id], 'time': now}
			is_new = True
		else:
			if not self._ids_reg[sub].get(rw_type):
				self._ids_reg[sub][rw_type] = [msg_id]
			else:
				_list = self._ids_reg[sub][rw_type]
				_list.append(msg_id)
				self._ids_reg[sub][rw_type] = _list
			self._ids_reg[sub]['time'] = now

		return is_new

	def was_send_resp(self, sub, rw_type):
		'''
		:param sub: #nick , that receiver
		:param rw_type: response type
		:return:  True if msg already was sent
		'''
		user = self._ids_reg.get(sub)
		if not user:
			return False

		type_msg = user.get(rw_type)
		if not type_msg:
			return False

		_time = user.get('time')
		if _time:
			# msg expire then can re send
			now = datetime.datetime.utcnow()
			if ((now - _time).seconds / 60) > EXPIRE_MINUTES:
				return False

		return True

	def fw_slack(self, msg, subject, group_name=None, channel=SLACK_CHANNEL):
		content = self.format_msg_slack(msg.content)
		text = '*{}* wrote:  \n {}'.format(subject, content)
		if group_name:
			text = '*{}* wrote in *{}*:  \n {}'.format(
				subject,
				group_name,
				content,
			)
			if SKYPE_SLACK_WRAPPER:
				channel = SKYPE_SLACK_WRAPPER.get(group_name, SLACK_CHANNEL)
				text = '*{}* : \n {}'.format(
					subject,
					content,
				)
		attachment = [
			{
				'text': '',
				'color': '#345',
			},
		]
		payload = {
			'username': SLACK_BOT_USERNAME,
			'icon_url': SLACK_BOT_ICON,
			'channel': channel,
			'text': text,
			# 'attachments': attachment, 
		}

		response = requests.post(SLACK_WEBHOOK, json=payload)

		return response

	def onEvent(self, event):
		if (
			isinstance(event, SkypeNewMessageEvent)
			and not event.msg.userId == self.userId
		):
			raw = event.raw
			group_name = raw.get('resource').get('threadtopic') 
			subject = raw.get('resource').get('imdisplayname', '')
			msg_id = raw.get('resource').get('id')
			response_type = 'auto_hi'
			response_type_at = 'auto_hi_at'
			sky_msg = SKY_MSG_RESPONSE.replace('@user', subject)
			sky_alternate_msg = SKY_MSG_RESPONSE_AT.replace('@user', subject)

			self.write_log(str(event.msg.content))
			self.write_log('******************')

			if group_name:
				response_type = 'auto_hi_group'

				# if I was quoted in the msg
				if self.check_regex(event.msg.content):
					if not self.was_send_resp(subject, response_type):
						event.msg.chat.sendMsg(sky_msg)
						self.ram_memory('{}_{}'.format(subject, group_name), msg_id, response_type)

					elif not self.was_send_resp(subject, response_type_at):
						event.msg.chat.sendMsg(sky_alternate_msg)
						self.ram_memory(subject, msg_id, response_type_at)

					if SLACK_CHANNEL_PERSONAL:
						self.fw_slack(event.msg, subject, group_name, channel=SLACK_CHANNEL_PERSONAL)
				else:
					self.fw_slack(event.msg, subject, group_name)

			elif not group_name:
				if not self.was_send_resp(subject, response_type):
					event.msg.chat.sendMsg(sky_msg)
					self.ram_memory(subject, msg_id, response_type)
				elif not self.was_send_resp(subject, response_type_at):
					event.msg.chat.sendMsg(sky_alternate_msg)
					self.ram_memory(subject, msg_id, response_type_at)

				if SLACK_CHANNEL_PERSONAL:
					self.fw_slack(event.msg, subject, group_name, channel=SLACK_CHANNEL_PERSONAL)

			self.write_log(str(self._ids_reg), level='debug')


def auto_reply(argv):
	sk_ping = SkypePing(SKY_USERNAME, SKY_PASSWORD)

	args = ' '.join(argv)
	print(args)
	log, tail, path, clear = False, False, False, False

	if re.search(r'-log(?:\s+|$)', args):
		log = True

	if re.search(r' -tail(?:\s+|$)', args):
		tail = True

	if re.search(r' -path(?:\s+|$)', args):
		path = True

	if re.search(r' -clear(?:\s+|$)', args):
		clear = True

	if log:
		log_path = sk_ping.log_path
		if path:
			print(log_path)
		elif not os.path.exists(log_path):
			logger.info('file not found')
		elif tail:
			command = 'tail -f {}'.format(sk_ping.log_path)
			process = subprocess.Popen(command.split())
			output, error = process.communicate()

		elif clear:
			backup_name = 'log_file_{}.log'.format(datetime.datetime.utcnow().date())
			backup_path = '/tmp/{}'.format(backup_name)
			shutil.copy(sk_ping.log_path, backup_path)
			# clear
			open(sk_ping.log_path, 'w').close()

		else:
			command = 'cat {}'.format(sk_ping.log_path)
			process = subprocess.Popen(command.split())
			output, error = process.communicate()
		return print('--- cmd---')

	sk_ping.start()


if __name__ == '__main__':
	try:
		auto_reply(sys.argv)

	except KeyboardInterrupt:
		pass

	except:
		exc_type, exc_value, exc_traceback = sys.exc_info()
		lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
		error = (''.join('!! ' + line for line in lines)).encode('utf-8')
		logger.error(error)

