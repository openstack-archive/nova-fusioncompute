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

import mock
from oslo_config import cfg

from nova import context
from nova import objects
from nova import test
from nova.tests import fake_instance

from nova.virt.fusioncomputeapi import driver
from nova.virt.fusioncomputeapi import taskops
from nova.fusioncompute.virt.huaweiapi import cluster as fc_cluster
from nova.fusioncompute.virt.huaweiapi.cluster import ClusterOps

import fake_fcclient as fake_fcclient

CONF = cfg.CONF
CONF.import_opt('compute_manager','nova.service')

class FusionComputeDriverStartupTestCase(test.NoDBTestCase):
    def setUp(self):
        super(FusionComputeDriverStartupTestCase, self).setUp()

        self.patcher = mock.patch('nova.fusioncompute.virt.huaweiapi.driver.FusionComputeDriver.__init__')
        self.mockClass = self.patcher.start()

        self.driver = driver.FusionComputeDriver(None)
        self.driver._client = None
        self.driver.task_ops = taskops.TaskOperation(self.driver)
        self.driver.cluster_ops = fc_cluster.ClusterOps(self.driver._client,
                                                        self.driver.task_ops)
        def tearDown(self):
            super(FusionComputeDriverStartupTestCase, self).tearDown()
            self.patcher.stop()

        @mock.patch.object(ClusterOps, 'list_all_clusters')
        def test_init_all_clusters(self, list_all_clusters):
            list_all_clusters.return_value = []
            self.assertEqual(self.driver._list_all_clusters(), [])
            list_all_clusters.assert_called_once_with()


