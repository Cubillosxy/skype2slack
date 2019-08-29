# -*- coding: utf-8 -*-
""" Module to manage skype BOT interactions """
import datetime
import re
import shutil
import subprocess
import sys
import os
import traceback

import logzero
from logzero import logger
import requests
from skpy import SkypeEventLoop, SkypeMsg
from skpy import SkypeNewMessageEvent
from skpy.core import SkypeApiException

from settings import SKYPE_SLACK_WRAPPER
from settings import SKY_MSG_RESPONSE
from settings import SKY_PASSWORD
from settings import SKY_MSG_RESPONSE_AT
from settings import EXPIRE_MINUTES
from settings import SLACK_CHANNEL_PERSONAL
from settings import SKY_USERNAME_NICK
from settings import SKY_USERNAME
from settings import SLACK_BOT_ICON
from settings import SLACK_BOT_USERNAME
from settings import SLACK_CHANNEL
from settings import SLACK_WEBHOOK


class SkypePing(SkypeEventLoop):
    """ Class to listing Skype events and perform interactions"""
    _ids_reg = {}

    def __init__(self, username, password):  # custom behavior pylint: disable=super-init-not-called
        # Setup rotating logfile with 3 rotations, each with a maximum filesize of 1MB:
        self.log_filename = 'skype_log.log'
        self.log_path = '/tmp/{}'.format(self.log_filename)
        self.token_path = '/tmp/{}'.format('skype_token')
        self.username = username
        self.password = password
        logzero.logfile(self.log_path, maxBytes=1e6, backupCount=3)

    def start(self):
        """ Method to start Skype Bot """
        self.write_log('sending credentials')
        super(SkypePing, self).__init__(self.username, self.password, self.token_path)
        self.write_log('connect ok')
        self.loop()

    @staticmethod
    def check_regex(content):
        """ Method to search regex match on both cases detected """
        username_regex = '{}.'.format(SKY_USERNAME)
        result_2 = False

        result_1 = re.search(username_regex, content)
        if SKY_USERNAME_NICK:
            nick_regex = '>{}<'.format(SKY_USERNAME_NICK)
            result_2 = re.search(nick_regex, content)
        return result_1 or result_2

    @staticmethod
    def write_log(content: str, level: str = 'info') -> None:
        """ Method to manage register logging """
        try:
            getattr(logger, level)(content.encode('utf-8'))
        except (AttributeError, TypeError):
            logger.error(msg='error trying to write, level: %s' % level)

    @staticmethod
    def format_at_msg(content: str) -> str:
        """
        Method to clean Skype Messages
        Args:
            content: A str describing row Skype message

        Returns:
            A str describing clean Skype message.
        """
        content = re.sub(r'<at.id="[a-zA-Z0-9_:\*\. \-]+">', '*@', content)
        content = re.sub(r'</at>', '*', content)
        return content

    def format_msg_slack(self, content: str) -> str:
        """
        Method to transform skype message to slack readable string
        Args:
            content: A str describing raw skype Content.

        Returns:
            A str describing a friendly sequence for slack.
        """
        quote_msg = re.findall(
            r'</legacyquote>([<>a-zA-Z ="/,\s\.\[\]\-0-9\(\)\\&:_;\'|\?@\*\!%]*)<legacyquote>',
            content
        )
        quote_msg_2 = re.findall(r'<legacyquote>([.\n]*)</legacyquote>', content)
        if quote_msg or quote_msg_2:
            author = re.findall(r'authorname="([a-zA-Z \-_0-9\.,\\]+)"?', content)[0]
            timestamp = float(re.findall(r'timestamp="([0-9 ]+)"', content)[0])
            time_format = datetime.datetime.fromtimestamp(timestamp).strftime(
                '%Y/%m/%d at %I:%M %p'
            )
            complement = re.findall(r'</quote>(.*)', content)[0]
            complement = self.format_at_msg(complement)
            quote = self.format_at_msg((quote_msg[0] or quote_msg_2[0]))

            # remove extend text
            quote = re.sub(
                (r'<e_m a="[a-zA-Z0-9_:\*\. \-]+".'
                 r'[a-zA-Z0-9_="]+.[a-zA-Z0-9_="]+.'
                 r'[a-zA-Z0-9_="]+></e_m>'),
                '',
                quote
            )

            text_quote = '>>>  {quote} <<< \n `{author}, {time_format}` \n {complement}'.format(
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

        # format &gt;
        text_quote = re.sub(r'&gt;', '>', text_quote)

        # TODO: replace skype emojis for slack - new feature pylint: disable=fixme
        return text_quote

    def ram_memory(self, sub, msg_id, rw_type):
        """

        Args:
            sub:
            msg_id:
            rw_type:

        Returns:

        """
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
        """

        Args:
            sub:
            rw_type:

        Returns:

        """
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

    def fw_slack(
            self, msg: SkypeMsg, subject: str, group_name: str = None, channel: str = SLACK_CHANNEL
    ) -> requests.Response:
        """
        Method to forward message from skype to Slack
        Args:
            msg: A SkypeMsg object to get skype message information.
            subject: A str describing slack subject message.
            group_name: A str describing slack group name.
            channel: A str describing slack channel to send message.

        Returns:
            A requests.Response object.
        """
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
        # attachment = [
        #     {
        #         'text': '',
        #         'color': '#345',
        #     },
        # ]
        payload = {
            'username': SLACK_BOT_USERNAME,
            'icon_url': SLACK_BOT_ICON,
            'channel': channel,
            'text': text,
            # 'attachments': attachment,
        }

        response = requests.post(SLACK_WEBHOOK, json=payload)

        return response

    def onEvent(self, event: SkypeNewMessageEvent) -> None:
        """ Method to dispatch handler to Skype Events """
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
                        self.fw_slack(
                            event.msg,
                            subject,
                            group_name,
                            channel=SLACK_CHANNEL_PERSONAL
                        )
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


def auto_reply(argv: list) -> None or str:
    """
    Routine to execute Skype Bot and manage script arguments
    Args:
        argv: A list describing sys arguments pass to script, the follow is the supported values:
        -log: Specify if action to perform on script if only to see logs.
        -tail: Only matter when -log is specified allow to show log lines on tail mode.
        -path: Only matter when -log is specified allow see specify log file.
        -clear: Only matter when -log is specified, clean log content.
        -supervisor: flag to execute Skype bot almost with one retry
        -inf: flag matter when -supervisor flag is specified and retry skypebot execution always.
    Raises:
        ValueError: case on too many values can happen
        TypeError: case where type of object pass is wrong or send bad arguments to some method.
        AttributeError: some error accessing or using one object attribute.
    Returns:
        A str describing process finalization
    """
    args = ' '.join(argv)
    print(args)
    sk_ping = None
    log = re.search(r'-log(?:\s+|$)', args)
    supervisor = re.search(r' -supervisor(?:\s+|$)', args)
    tail = re.search(r' -tail(?:\s+|$)', args)
    path = re.search(r' -path(?:\s+|$)', args)
    clear = re.search(r' -clear(?:\s+|$)', args)

    if log:
        sk_ping = SkypePing(SKY_USERNAME, SKY_PASSWORD)

    logger.info(msg='run on %s' % ('supervisor' if supervisor else 'log'))

    infinite = re.search(r' -inf(?:\s+|$)', args)
    if log and path:
        print(sk_ping.log_path)
    elif log and not os.path.exists(sk_ping.log_path):
        logger.info('file not found')
    elif log and tail:
        process = subprocess.Popen(
            'tail -f {0}'.format(sk_ping.log_path).split()
        )
        process.communicate()
    elif log and clear:
        shutil.copy(
            sk_ping.log_path,
            '/tmp/log_file_{0}'.format(datetime.datetime.utcnow().date())
        )
        open(sk_ping.log_path, 'w').close()  # clear
    elif log:
        process = subprocess.Popen(
            'cat {0}'.format(sk_ping.log_path).split()
        )
        process.communicate()
    elif supervisor and infinite:
        while True:
            try:
                SkypePing(SKY_USERNAME, SKY_PASSWORD).start()
            except SkypeApiException:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
                error = (''.join('!! ' + line for line in lines)).encode('utf-8')
                logger.error(error)
    elif supervisor:
        try:
            SkypePing(SKY_USERNAME, SKY_PASSWORD).start()
        except SkypeApiException:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
            error = (''.join('!! ' + line for line in lines)).encode('utf-8')
            logger.error(error)
            SkypePing(SKY_USERNAME, SKY_PASSWORD).start()

    logger.info('--- cmd---')
    return 'process end'


if __name__ == '__main__':
    """ Function to execute Sky Bot """
    try:
        auto_reply(sys.argv)
    except KeyboardInterrupt:
        pass

    except:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
        error = (''.join('!! ' + line for line in lines)).encode('utf-8')
        logger.error(error)
