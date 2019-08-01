
import re
import requests
import datetime
from skpy import Skype
from skpy import SkypeEventLoop
from skpy import SkypeNewMessageEvent

from settings import SKY_PASSWORD, SKY_MSG_RESPONSE_AT, EXPIRE_MINUTES, SLACK_CHANNEL_PERSONAL, SKY_USERNAME_NICK
from settings import SLACK_CHANNEL
from settings import SLACK_BOT_ICON
from settings import SKY_MSG_RESPONSE
from settings import SKY_USERNAME
from settings import SLACK_WEBHOOK
from settings import SLACK_BOT_USERNAME
from settings import SKYPE_SLACK_WRAPPER


class SkypePing(SkypeEventLoop):
	_ids_reg = {}


	def __init__(self, username, password):
		super(SkypePing, self).__init__(username, password)

	@staticmethod
	def check_regex(content):
		username_regex = '{}.'.format(SKY_USERNAME)
		result_2 = False

		result_1 = re.search(username_regex, content)
		if SKY_USERNAME_NICK:
			nick_regex = '>{}<'.format(SKY_USERNAME_NICK)
			result_2 = re.search(nick_regex, content)
		return result_1 or result_2

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
		content = msg.content
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

		payload = {
			'username': SLACK_BOT_USERNAME,
			'icon_url': SLACK_BOT_ICON,
			'channel': channel,
			'text': text
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

			print(event.msg.content)
			print('******************')
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

			print('---%%%%%%%----')
			print(self._ids_reg)
			print('---%%%%%%%----')


def auto_reply():
	print('sending credentials')
	sk_ping = SkypePing(SKY_USERNAME, SKY_PASSWORD)
	print('connect ok')
	sk_ping.loop()


if __name__ == '__main__':
	auto_reply()
