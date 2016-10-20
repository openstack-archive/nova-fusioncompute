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

import ConfigParser

SPLIT_TAG = '_'


class OSConfigBase(dict):
    """
    Base Class
    """

    def __init__(self):
        super(OSConfigBase, self).__init__()
        self._config = ConfigParser.ConfigParser()
        self._sections = []

    def __getitem__(self, item):
        if item.lower() in self:
            return super(OSConfigBase, self).__getitem__(item.lower())
        raise KeyError

    def get(self, k, d=None):
        if k.lower() in self:
            return super(OSConfigBase, self).get(k.lower(), d)
        return d

    def _config_to_dict(self):
        """
        Change config to dict, must implement in sub class
        """
        raise NotImplementedError()

    def __call__(self, config_file=None):
        if config_file:
            self._config.read(config_file)
            self._sections = self._config.sections()
            self._config_to_dict()


class OSConfigInt(OSConfigBase):
    """
    Get Int-Type fc os version from Str_Type
    windows 7 enterprise 32bit --> 25
    """

    def __init__(self):
        super(OSConfigInt, self).__init__()

    def _config_to_dict(self):
        for section in self._sections:
            self[section] = {}
            for key, value in self._config.items(section):
                self[section][str(key).replace(SPLIT_TAG, ' ')] = value


class OSConfigStr(OSConfigBase):
    """
    Get Str_Type fc os version from Int-Type
    25 --> windows 7 enterprise 32bit
    """

    def __init__(self):
        super(OSConfigStr, self).__init__()

    def _config_to_dict(self):
        for section in self._sections:
            self[section] = {}
            for key, value in self._config.items(section):
                self[section][value] = str(key).replace(SPLIT_TAG, ' ')

OS_VERSION_INT = OSConfigInt()
OS_VERSION_STR = OSConfigStr()
VIRTUAL_IO_OS_VERSION_INT = OSConfigInt()
