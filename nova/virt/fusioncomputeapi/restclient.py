"""
    Basic REST Client
"""

import requests
import copy

from oslo_serialization import jsonutils
from nova.i18n import _
from nova.virt.fusioncomputeapi import utils
from nova.virt.fusioncomputeapi.utils import LOG

class RestClient(object):
    """
    send rest msg class
    """
    def __init__(self, host, port=80, ssl=None, cert=None):
        self.host = host
        self.port = port
        self.__ssl = ssl
        self.__cert = cert

        self.__protocol = 'http' if not self.__ssl else 'https'

    def __repr__(self):
        """
        get rest path msg
        :return:
        """
        return 'REST client %s://%s:%s' % (
            self.__protocol, self.host, self.port)

    def _to_url(self, path):
        """
        get rest url
        :param path:
        :return:
        """
        return '%s://%s:%s%s' % (
            self.__protocol, self.host, self.port, path)

    def _request(self, method, path, data=None, headers=None, **kwargs):
        """
        send request msg
        :param method:
        :param path:
        :param data:
        :param headers:
        :param kwargs:
        :return:
        """

        url = self._to_url(path)

        if not data:
            data = jsonutils.dumps({})
        elif isinstance(data, dict) or isinstance(data, list):
            data = jsonutils.dumps(data)

        if method == 'get':
            log_fun = LOG.debug
        else:
            log_fun = LOG.info

        try:
            data_for_log = copy.deepcopy(jsonutils.loads(data))
            utils.drop_password_key(data_for_log)
            log_fun(_('request: %s %s %s'), method, url,
                    jsonutils.dumps(data_for_log))

        except Exception:
            log_fun(_('request: %s %s'), method, url)

        rsp = requests.request(method, url, data=data, headers=headers,
                               verify=False, **kwargs)
        return rsp

    def request_msg(self, method, path, data=None, headers=None, **kwargs):
        """
        send rest message base func, should achieve in child class
        :param method:
        :param path:
        :param data:
        :param headers:
        :param kwargs:
        :return:
        """
        return self._request(method, path, data=data, headers=headers,
                             **kwargs)

    def post(self, path, data=None, **kwargs):
        """Post.

        :param path: path under Context, something like '/app/resource'
        :param data: (Optional) data of request
        :param kwargs: headers, etc.
        :return: Response object in requests
        """
        return self.request_msg('post', path, data=data, **kwargs)

    def get(self, path, **kwargs):
        """Get.

        :param path: path under Context, something like '/app/resource/id'
        :param kwargs:  headers, etc.
        :return: Response object in requests
        """
        return self.request_msg('get', path, **kwargs)

    def put(self, path, data=None, **kwargs):
        """Put.

        :param path: path under Context, something like '/app/resource/id'
        :param data: (Optional) data of request
        :param kwargs: headers, etc.
        :return: Response object in requests
        """
        return self.request_msg('put', path, data=data, **kwargs)

    def delete(self, path, **kwargs):
        """Delete.

        :param path: path under Context, something like '/app/resource/id'
        :param kwargs: headers, etc.
        :return: Response object in requests
        """
        return self.request_msg('delete', path, **kwargs)
