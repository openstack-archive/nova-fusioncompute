# Copyright 2016 Huawei Technologies Co.,LTD.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from nova.i18n import _
from nova.virt.fusioncomputeapi import restclient
from nova.virt.fusioncomputeapi import exception
from nova.virt.fusioncomputeapi import utils
from nova.virt.fusioncomputeapi.utils import LOG
from nova.virt.fusioncomputeapi import constant


class FCBaseClient(restclient.RestClient):
    """
    fc send rest message class
    """
    STATUS_OK = [200, 201, 202]
    STATUS_NO_AUTH = [401]
    STATUS_INVALID = [400, 403, 404, 500, 503]

    def __init__(self, host, user, key, user_type, api_version='6.0',
                 ssl=None, port=None, cert=None, request_time_out=120):
        super(FCBaseClient, self).__init__(host, port=port, ssl=ssl, cert=cert)

        self.__user = user
        self.__key = key
        self.__user_type = user_type

        self.__api_version = api_version
        self.__accept = ('application/json;version=%s;charset=UTF-8' %
                         api_version)
        self.__content_type = 'application/json'
        self.__accept_language = 'en_US'

        self.__request_time_out = request_time_out
        self.__token = None

        self.context = FCClientContext(self)

    def _update_and_get_headers(self, headers, force_get_token):
        """
        update fc rest header and return headers
        :param headers:
        :param force_get_token:
        :return:
        """
        if not self.__token or force_get_token:
            self.get_token()
        if not headers:
            headers_res = self._make_headers(self.__token)
        else:
            headers_res = headers.copy()
            headers_res.update(self._make_headers(self.__token))
        return headers_res

    def request_msg(self, method, path, data=None, headers=None, **kwargs):
        req_headers = self._update_and_get_headers(headers, False)

        # set default request time out
        kwargs['timeout'] = kwargs.get('timeout', self.__request_time_out)
        rsp = self._request(method, path, data, headers=req_headers, **kwargs)

        if rsp.status_code in self.STATUS_NO_AUTH:
            LOG.info('token may expired, fetch again.')
            req_headers = self._update_and_get_headers(headers, True)
            rsp = self._request(method, path, data, headers=req_headers,
                                **kwargs)

        # catch message sending exception
        self._raise_if_not_in_status_ok(rsp)
        ret_data = {'response': rsp, 'data': None}

        if rsp.text:
            try:
                ret_data['data'] = rsp.json()
            # ignore pylint:disable=W0703
            except Exception as excp:
                LOG.warn(_('failed to loads json response data, %s'), excp)
                ret_data['data'] = rsp.text

        if kwargs.get('need_response', False):
            return ret_data
        return ret_data['data']

    def _raise_if_not_in_status_ok(self, rsp):
        """
        if response is not normal,rasise exception
        :param rsp:
        :return:
        """
        if rsp.status_code not in self.STATUS_OK:
            error_info = {}
            try:
                error_info = rsp.json()
            # ignore pylint:disable=W0703
            except Exception as excp:
                LOG.warn('try to get error response content failed: %s', excp)

            LOG.error(_('FC request error: <status_code> %s <reason> '
                        '%s <url> %s <errorcode> %s <errorDes> %s'),
                      rsp.status_code, rsp.reason, rsp.url,
                      error_info.get('errorCode', 'unknown'),
                      error_info.get('errorDes', 'unknown'))

            raise exception.RequestError(reason=error_info.get('errorDes'),
                                         error_code=error_info.get('errorCode')
                                         )

    def get_token(self):
        """ Get token from FC
        :return:
        """
        response = self._request('post', constant.TOKEN_URI, data={},
                                 headers=self._make_headers())
        self.__token = response.headers['X-Auth-Token']

    def get_sites(self):
        """
        get fc default site info
        :return:
        """
        return self.get(constant.SITE_URI)

    def get_first_site(self):
        """
        get fc first siet
        :return:
        """
        sites = self.get_sites()
        if not sites or not sites.get('sites'):
            raise exception.NoAvailableSite()
        return sites['sites'][0]

    def set_default_site(self):
        """
        set fc client default site info
        :return:
        """
        self.context.set_default_site(self.get_first_site())

    def _make_headers(self, token=None):
        """
        make token header info
        :param token:
        :return:
        """
        headers = {
            'Accept-Language': self.__accept_language,
            'Content-Type': self.__content_type,
            'Accept': self.__accept
        }

        if token:
            headers.update({
                'X-Auth-Token': token
            })
        else:
            headers.update({
                'X-Auth-User': self.__user,
                'X-Auth-Key': self.__key,
                'X-Auth-UserType': self.__user_type,
                'X-ENCRIPT-ALGORITHM': '1'
            })
        return headers


class FCClientContext(dict):
    """
    fc base info
    """

    def __init__(self, client):
        super(FCClientContext, self).__init__()
        self.client = client
        self.site_uri_map = None

    def __getattr__(self, name):
        """
        if dict has attr,return dict ,else return site uri info
        :param name:
        :return:
        """
        if self.get(name):
            return self.get(name)
        elif self.site_uri_map:
            return utils.get_fc_uri(name, self.site_uri_map)
        else:
            return None

    def set_default_site(self, site):
        """
        set default site infos
        :param site:
        :return:
        """
        self['site'] = site
        self['site_id'] = utils.get_id_from_urn(self['site']['urn'])
        self['site_uri'] = '/'.join([constant.SITE_URI, self['site_id']])

        self.site_uri_map = {'site_uri': self['site_uri']}

    def get_path_by_site(self, path='', **kwargs):
        """Connect your path with default site path, and format args value

        :param path: in format like '/resource/%<id>s/action/%(other)s'
        :param kwargs: Dictionary args, matched path format, like (id=id_value,
        other=other_value)
        :return: path like
        '/service/sites/site_id/resource/id_value/action/other_value'
        """
        if not kwargs:
            kwargs = {}

        if isinstance(path, list):
            path = ''.join(path)

        return ''.join([self['site_uri'], path % kwargs])
