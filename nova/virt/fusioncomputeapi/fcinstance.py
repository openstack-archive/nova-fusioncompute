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

import time

from nova import exception
from nova.compute import power_state
from nova.i18n import _

from nova.virt.fusioncomputeapi import ops_base
from nova.virt.fusioncomputeapi import utils
from nova.virt.fusioncomputeapi import constant
from nova.virt.fusioncomputeapi.utils import LOG


class FCInstance(dict):
    """
    fc vm class
    """

    def __init__(self, ini_dict):
        super(FCInstance, self).__init__()
        for key in ini_dict:
            self[key] = ini_dict[key]

    def get_vm_action_uri(self, action):
        """
        return fc vms uri info
        :param action:
        :return:
        """
        return self.uri + constant.VM_URI_MAP[action]

    def __getattr__(self, name):
        return self.get(name)


class FCInstanceOps(ops_base.OpsBase):
    """
    fc instances manager
    """

    def _query_vm(self, **kwargs):
        """Query VMs.

        :param kwargs:
                    name: VM name
                    status: VM status
                    scope: VM in certain scope
        :return: list of VMs
        """
        return self.get(utils.build_uri_with_params(self.site.vm_uri, kwargs))

    def _get_fc_vm(self, vm_info, limit=1, offset=0, detail=2, **kwargs):
        """
        get fv vm info by conditions
        :param vm_info:
        :param limit:
        :param offset:
        :param detail:
        :param kwargs:
        :return:
        """
        instances = self._query_vm(limit=limit, offset=offset, detail=detail,
                                   **kwargs)
        if not instances or not instances['vms']:
            LOG.error(_("can not find instance %s."), vm_info)
            raise exception.InstanceNotFound(instance_id=vm_info)
        return FCInstance(instances['vms'][0])

    def get_vm_state(self, instance):
        """

        :param instance:
        :return:
        """
        return self.get_vm_by_uuid(instance)

    def get_total_vm_numbers(self, **kwargs):
        """
        Get total numbers in fc
        :return:
        """
        instances = self._query_vm(limit=1, offset=0, detail=0, **kwargs)
        if not instances or not instances.get('total'):
            return 0
        total = int(instances.get('total'))
        LOG.info(_("total instance number is %d."), total)
        return total

    def get_all_vms_info(self, **kwargs):
        """
        Get all vms info by paging query
        :return: {uuid:state, ...}
        """

        states = {}

        limit = 100
        total = self.get_total_vm_numbers(**kwargs)
        while len(states) < total:
            last_total = len(states)
            instances = self._query_vm(limit=limit, offset=len(states),
                                       detail=2, **kwargs)
            for instance in instances.get('vms'):
                if instance.get('params') is not None and instance.get(
                        'params').get("externalUuid") is not None:
                    states[
                        instance["params"]['externalUuid']] = constant.VM_POWER_STATE_MAPPING.get(
                        instance['status'], power_state.NOSTATE)
                else:
                    states[instance['uuid']] = constant.VM_POWER_STATE_MAPPING.get(
                        instance['status'], power_state.NOSTATE)
            if len(instances.get('vms')) < limit:
                break
            if last_total == len(states):
                break
            time.sleep(0.005)
        return states

    def get_all_vms(self, **kwargs):
        """
        Get all vms by paging query
        Here only return at most 100 vms to avoid timeout in db query
        :return:
        """

        instances = []
        total = self.get_total_vm_numbers(**kwargs)
        while len(instances) < total:
            paging_instances = self._query_vm(limit=100, offset=len(instances),
                                              detail=2, **kwargs)
            instances += paging_instances.get('vms')
            break
        for instance in instances:
            if instance.get('params') is not None and instance.get(
                    'params').get("externalUuid") is not None:
                instance["uuid"] = instance["params"]['externalUuid']
        return instances

    def get_vm_by_uuid(self, instance):
        """
        get vm info by vm uuid
        :param instance: openstack vm info
        :return:inner vm info
        """

        try:
            vm_id = instance.system_metadata.get('fc_vm_id')
            if vm_id and vm_id.startswith('i-') and (len(vm_id) == 10):
                instance = self.get('%s/%s' % (self.site.vm_uri, vm_id))
                return FCInstance(instance)
        except Exception:
            pass

        return self._get_fc_vm_by_uuid_and_external_uuid(
            instance['uuid'], externalUuid=instance['uuid'])

    def get_vm_by_id(self, vm_id):
        """

        :param vm_id:
        """
        return self._get_fc_vm(vm_id, vmId=vm_id)

    def get_vm_by_name(self, instance_name):
        """
        # NOTE: this method is used for implementing
        # nova.virt.driver.ComputeDriver#instance_exists
        :param instance_name:
        :return:
        """
        return self._get_fc_vm(instance_name, name=instance_name)

    def _get_fc_vm_by_uuid_and_external_uuid(
            self, vm_info, limit=1, offset=0, detail=2, **kwargs):
        """
        get fv vm info by conditions
        :param vm_info:
        :param limit:
        :param offset:
        :param detail:
        :param kwargs:
        :return:vms[0]
        """
        # find vm by external_uuid or find vm by uuid for upgrade
        instances = self._query_vm(
            limit=limit,
            offset=offset,
            detail=detail,
            **kwargs)
        if not instances or not instances['vms']:
            instances_by_uuids = self._query_vm(
                limit=limit, offset=offset, detail=detail, uuid=vm_info)
            if not instances_by_uuids or not instances_by_uuids['vms']:
                LOG.error(_("can not find instance %s."), vm_info)
                raise exception.InstanceNotFound(instance_id=vm_info)
            return FCInstance(instances_by_uuids['vms'][0])
        return FCInstance(instances['vms'][0])

FC_INSTANCE_MANAGER = FCInstanceOps(None)
