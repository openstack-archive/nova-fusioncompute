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

from nova import test
import oslo_config

from nova.virt.fusioncomputeapi import constant as cfg

CONF = cfg.CONF

class TestConf(test.TestCase):
    def setUp(self):
        super(TestConf, self).setUp()

    def test_conf(self):
        """Tests that fusioncompute config values are configured."""
        # Try an option from each grouping of static options

        # FC Ip
        self.assertEqual('', CONF.fusioncompute.fc_ip)
