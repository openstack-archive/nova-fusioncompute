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
import random
import time


from nova.i18n import _
from nova.virt.fusioncomputeapi import exception as fc_exc
from nova.virt.fusioncomputeapi import ops_base
from nova.virt.fusioncomputeapi.utils import LOG
from oslo_service import loopingcall


def wait_task_done(task_ops, exc=None, fixedInterval=0):
    """wait_task_done

    Send message and wait task result. Only for the function(func) whose
    return like {"taskUrn": string, "taskUri": string} format, if you
    won't want to send and wait the result, return {} instead of
    {"taskUrn": string, "taskUri": string} format

    :param task_ops: the task monitor object
    :param exc: when monitor the task failed, raise this exception object
    :fixedInterval: when fixedInterval =0 , the task query period is
      random(interval + random()*3).
    when fixedInterval !=0, the query period is fixed to fixedInterval
    :return:
    """
    def wrap(func):
        """wrap function

        :param func: the function will be decorated
        :return:
        """
        @functools.wraps(func)
        def inner(*args, **kwargs):
            """inner function

            :param args: the list format args of function that will
            be decorated
            :param kwargs: the dict format args of function that will
            be decorated
            :return:
            """
            try:
                resp = func(*args, **kwargs)
            except fc_exc.RequestError as req_exc:
                if exc:
                    raise exc(str(req_exc.kwargs['reason']))
                raise req_exc

            if isinstance(resp, dict) and resp.get('taskUri'):
                if fixedInterval != 0:
                    success, reason = task_ops.wait_task_done(
                        resp['taskUri'], 3, fixedInterval)
                else:
                    success, reason = task_ops.wait_task_done(resp['taskUri'])
                if not success:
                    LOG.error(_('task failed: %s'), reason)
                    if exc:
                        raise exc(str(reason))
                    raise fc_exc.FusionComputeTaskException(reason=reason)

            return resp
        return inner
    return wrap


class TaskOperation(ops_base.OpsBase):
    """task operation object

    """

    def __init__(self, fc_client):
        """TaskOperation init func

        :param fc_client:
        :return:
        """
        super(TaskOperation, self).__init__(fc_client)

    def wait_task_done(self, task_uri, interval=3, fixedInterval=0):
        """wait_task_done

        :param task_uri:
        :param interval:
        :return:
        """
        if fixedInterval == 0:
            random.seed()
            f = random.random()
            f = f * 3
            interval = interval + f
        else:
            interval = fixedInterval

        ret = {'success': False, 'reason': None}

        def _wait_done():
            """wait task result

            """
            num = 3
            for tmp in range(num):
                try:
                    task = self.get_task(task_uri)
                    break
                except Exception as e:
                    LOG.info(_('Get task uri falied %d') % tmp)
                    if tmp >= (num - 1):
                        raise e
                    time.sleep(10)
                    continue

            if task['status'] == "success":
                ret['success'] = True
                raise loopingcall.LoopingCallDone()
            elif task['status'] == "failed":
                ret['reason'] = task['reasonDes']
                raise loopingcall.LoopingCallDone()
            else:
                LOG.info(_("Task [%s] is running,"), task_uri)

        timer = loopingcall.FixedIntervalLoopingCall(_wait_done)
        timer.start(interval=interval).wait()
        return ret['success'], ret['reason']

    def get_task(self, task_uri):
        """get task uri info

        :param task_uri:
        :return:
        """
        return self.get(task_uri)
