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

from nova.virt.fusioncomputeapi import ops_base
from nova.virt.fusioncomputeapi import taskops


class OpsTaskBase(ops_base.OpsBase):
    """fc operation with task obj

    """

    def __init__(self, fc_client, task_ops):
        super(OpsTaskBase, self).__init__(fc_client)
        self.task_ops = task_ops

    def post(self, path, data=None, excp=None, fixedInterval=0, **kwargs):
        """Post.

        :param path: path under Context, something like '/app/resource'
        :param data: (Optional) data of request
        :param kwargs: headers, etc.
        :return: Response object in requests
        """
        @taskops.wait_task_done(self.task_ops, excp, fixedInterval)
        def _post():
            """inner post func

            """
            # ignore pylint:disable=W0142
            return super(OpsTaskBase, self).post(path, data, **kwargs)
        return _post()

    def put(self, path, data=None, excp=None, fixedInterval=0, **kwargs):
        """Put.

        :param path: path under Context, something like '/app/resource/id'
        :param data: (Optional) data of request
        :param kwargs: headers, etc.
        :return: Response object in requests
        """
        @taskops.wait_task_done(self.task_ops, excp, fixedInterval)
        def _put():
            """inner put func

            """
            # ignore pylint:disable=W0142
            return super(OpsTaskBase, self).put(path, data, **kwargs)
        return _put()

    def delete(self, path, excp=None, **kwargs):
        """Delete.

        :param path: path under Context, something like '/app/resource/id'
        :param kwargs: headers, etc.
        :return: Response object in requests
        """
        @taskops.wait_task_done(self.task_ops, excp)
        def _delete():
            """inner delete func

            :return:
            """
            # ignore pylint:disable=W0142
            return super(OpsTaskBase, self).delete(path, **kwargs)
        return _delete()
