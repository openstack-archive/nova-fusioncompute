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
import functools
import hashlib
import sys
import traceback
from threading import Thread


from nova.i18n import _
from nova.virt.fusioncomputeapi import constant
from nova.virt.fusioncomputeapi import exception
from oslo_config import cfg
from oslo_log import log as logging


CONF = cfg.CONF
LOG = logging.getLogger(__name__)


def log_exception(exception=None):
    """log_exception

    :param exception:
    :return:
    """

    if exception:
        pass

    etype, value, track_tb = sys.exc_info()
    error_list = traceback.format_exception(etype, value, track_tb)
    for error_info in error_list:
        LOG.error(error_info)


def func_log_circle(instance=None, exceptions=None):
    """exec func, print func begin and end

    :param instance:
    :return:
    """

    def wrap(func):
        """wrap function

        :param func: the function will be decorated
        :return:
        """

        def _get_func_str(step):
            """get function pring string

            :param step:
            :return:
            """
            if instance:
                return _('%s '
                         '%s'
                         ' %s.') % \
                    (func.__name__, instance['uuid'], step)
            else:
                return _('%s '
                         '%s.') % (func.__name__, step)

        @functools.wraps(func)
        def inner(*args, **kwargs):
            """inner function

            :param args: the list format args of function that will
            be decorated
            :param kwargs: the dict format args of function that will
            be decorated
            :return:
            """

            LOG.info(_get_func_str('begin'))
            try:
                result = func(*args, **kwargs)
            except Exception as excp:
                LOG.error('%s traceback begin.', _get_func_str('failed'))
                log_exception(excp)
                LOG.error('%s traceback end.', _get_func_str('failed'))
                if exceptions is not None:
                    raise exceptions
                raise excp
            LOG.info(_get_func_str('success'))
            return result

        return inner

    return wrap


def get_id_from_urn(urn, regex=constant.ID_IN_URN_REGEX):
    """get vminfo by vm urn

    :param urn:
    :param regex:
    :return:
    """
    match = regex.search(urn)
    if not match:
        return ValueError(message='get id from URN failed')

    return match.group('id')


def build_uri_with_params(uri, param_map):
    """build uri with params

    :param uri:
    :param param_map:
    :return:
    """
    return ''.join([
        uri,
        '?',
        '&'.join(['%s=%s' % (k, v) for (k, v) in param_map.iteritems()])
    ])


def generate_uri_from_urn(urn):
    """generate uri with urn

    urn: urn:sites:4D6B0918:clusters:640
    uri: /service/sites/4D6B0918/clusters/640
    :return:
    """
    if urn:
        return urn.replace('urn', '/service').replace(':', '/')
    return None


def generate_urn_from_uri(uri):
    """generate uri with urn

    uri: /service/sites/4D6B0918/clusters/640
    urn: urn:sites:4D6B0918:clusters:640
    :return:
    """
    if uri:
        return uri.replace('/service', 'urn').replace('/', ':')
    return None


def image_size_to_gb(image_size):
    """image size sava as kb, fc disk size is gb, should trance

    :param image_size: image bytes size
    :return:image gb size
    """
    if not isinstance(image_size, int):
        return None
    else:
        gb_size = image_size / 1024 / 1024 / 1024
        if gb_size == 0:
            return 1
        else:
            return gb_size


def image_size_to_byte(image_size):
    """image_size_to_byte

    :param image_size: gb
    :return:
    """
    if not isinstance(image_size, int):
        return None
    else:
        return image_size * 1024 * 1024 * 1024


def get_fc_uri(fc_uri, base_uri_map):
    """get fc uri info

    :param fc_uri:uri key
    :param base_uri_map:uri params map
    :return:
    """
    baseuri = constant.FC_SITE_URI_MAP[fc_uri]['baseuri']
    dependuri = constant.FC_SITE_URI_MAP[fc_uri].get('dependuri')
    if dependuri:
        for uri_key in dependuri:
            base_uri_map[uri_key] = get_fc_uri(uri_key, base_uri_map)
    return baseuri % base_uri_map


def get_boot_option_from_metadata(metadata):
    """get_boot_option_from_metadata

    :param metadata:
    :return:
    """
    if not metadata:
        return constant.BOOT_OPTION_MAP['default']

    boot_option = metadata.get('__bootDev', 'default')
    if boot_option not in constant.BOOT_OPTION_MAP:
        LOG.warn(_('Invalid __bootDev: %s, use default instead'), boot_option)
        return constant.BOOT_OPTION_MAP['default']

    return constant.BOOT_OPTION_MAP[boot_option]


def get_vnc_key_map_setting_from_metadata(metadata):
    """get_vnc_key_map_setting_from_metadata

    :param metadata:
    :return:
    """
    # if metadata:
    #    keymapsetting = metadata.get('__vnc_keymap', 'default')
    #    if keymapsetting in constant.VNC_KEY_MAP_SETTING:
    #        LOG.info(_('The keymapsetting is %s'), keymapsetting)
    #        return constant.VNC_KEY_MAP_SETTING[keymapsetting]

    # LOG.warn(_('Invalid __vnc_keymap info , use conf instead'))
    # keymapsetting = CONF.vnc_keymap
    # if keymapsetting not in constant.VNC_KEY_MAP_SETTING:
    return constant.VNC_KEY_MAP_SETTING['default']
    # return constant.VNC_KEY_MAP_SETTING[keymapsetting]


def fc_qos_convert(input_dict, refer_key,
                   out_key, vcpus=1):
    """fc_qos_convert

    :param input_dict:
    :param refer_key:
    :param out_key:
    :param vcpus:
    :return:
    """
    rsp_dict = {}
    if input_dict is None:
        input_dict = {}
    df_values = constant.CPU_QOS_FC_DEFAULT_VALUE
    zipped = zip(refer_key, out_key, df_values)

    for src, dst, df_value in zipped:
        value = input_dict.get(src)
        if value is None:
            if src == 'weight' or src == 'quota:cpu_shares':
                rsp_dict[dst] = df_value * vcpus
            else:
                rsp_dict[dst] = df_value
        else:
            rsp_dict[dst] = value
    return rsp_dict


def dict_add(dict1=None, dict2=None):
    """dict_add

    :param dict1:
    :param dict2:
    :return:
    """
    rsp_dict = {}
    if dict1:
        rsp_dict.update(dict1.items())
    if dict2:
        rsp_dict.update(dict2.items())
    return rsp_dict


def split_strip(source_str, sep_str=','):
    """split source_str,return splited str strip

    :param source_str:
    :param sep_str:
    :return:
    """
    if len(source_str.strip()) == 0:
        return []
    split_list = source_str.split(sep_str)
    return [split_str.strip() for split_str in split_list]

ENCRYPT_LIST = ['password', 'vncpassword', 'oldpassword', 'domainpassword',
                'vncoldpassword', 'vncnewpassword', 'accessKey', 'secretKey',
                'isUpdateVmPassword', 'token']


def drop_password_key(data):
    """remove json password key item

    :param data:
    :return:
    """
    if not isinstance(data, dict):
        return

    for key in data.keys():
        if key in ENCRYPT_LIST:
            del data[key]
        elif data[key] and isinstance(data[key], dict):
            drop_password_key(data[key])


def sha256_based_key(key):
    """generate sha256 based key

    :param key:
    :return:
    """
    hash_ = hashlib.sha256()
    hash_.update(key)
    return hash_.hexdigest()


class TimeoutException(Exception):
    pass

ThreadStop = Thread._Thread__stop


def timelimited(timeout):
    """set fc request timeout len

    :param timeout:
    :return:
    """
    def decorator(function):

        def decorator2(*args, **kwargs):
            class TimeLimited(Thread):

                def __init__(self, _error=None):
                    Thread.__init__(self)
                    self._error = _error

                def run(self):
                    try:
                        self.result = function(*args, **kwargs)
                    except Exception as e:
                        LOG.debug(_("TimeLimited run Exception: %s") % e)
                        self._error = e

                def _stop(self):
                    if self.isAlive():
                        ThreadStop(self)

            t = TimeLimited()
            t.start()
            t.join(timeout)

            if isinstance(t._error, TimeoutException):
                LOG.debug(_("t._error %s"), t._error)
                t._stop()
                raise exception.RequestError(reason='request fc timeout',
                                             error_code='503')
            if t.isAlive():
                LOG.info(_("t.isAlive"))
                t._stop()
                raise exception.TimeoutError(reason='request timeout',
                                             error_code='503')
            if t._error is None:
                LOG.debug(_("t._error is None"))
                return t.result
            else:
                LOG.error(_("t._error %s"), t._error)
                raise t._error

        return decorator2
    return decorator
