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
import ast

from nova import context as nova_context
from nova import exception
from nova import objects
from nova import utils as nova_utils

from nova.compute import power_state
from nova.compute import task_states
from nova.console import type as ctype
from nova.i18n import _
from nova.image import glance
from nova.scheduler import client as scheduler_client
from oslo_serialization import jsonutils
from oslo_service import loopingcall
from oslo_utils import excutils


from nova.virt.fusioncomputeapi import constant
from nova.virt.fusioncomputeapi import exception as fc_exc
from nova.virt.fusioncomputeapi.fcinstance import FC_INSTANCE_MANAGER as FC_MGR
from nova.virt.fusioncomputeapi import ops_task_base
from nova.virt.fusioncomputeapi import type as hwtype
from nova.virt.fusioncomputeapi import utils
from nova.virt.fusioncomputeapi.utils import LOG
from nova.virt.fusioncomputeapi import vmcreation


INSTANCES_ACTION_SEMAPHORE = "%s-action-conflict"


class ComputeOps(ops_task_base.OpsTaskBase):
    """computer option"""

    def __init__(self, fc_client, task_ops, network_ops, volume_ops,
                 cluster_ops):
        super(ComputeOps, self).__init__(fc_client, task_ops)
        self.scheduler_client = scheduler_client.SchedulerClient()

        self._network_ops = network_ops
        self._volume_ops = volume_ops
        self._cluster_ops = cluster_ops

        self._init_os_config()

    def _init_os_config(self):
        """_init_os_config

        :return:
        """
        constant.HUAWEI_OS_VERSION_INT(config_file=constant.OS_CONFIG_FILE)
        constant.HUAWEI_OS_VERSION_STR(config_file=constant.OS_CONFIG_FILE)
        constant.HUAWEI_VIRTUAL_IO_OS_VERSION_INT(
            config_file=constant.VIRTUAL_IO_OS_CONFIG_FILE)

        os_type = constant.DEFAULT_HUAWEI_OS_TYPE
        os_version = constant.DEFAULT_HUAWEI_OS_VERSION.lower()
        constant.DEFAULT_HUAWEI_OS_CONFIG = [
            os_type,
            int(constant.HUAWEI_OS_VERSION_INT[os_type][os_version])
        ]

        constant.VIRTUAL_IO_OS_LIST = []
        if constant.CONF.fusioncompute.enable_virtualio:
            for os_type in constant.HUAWEI_VIRTUAL_IO_OS_VERSION_INT.keys():
                for os_version in constant.HUAWEI_VIRTUAL_IO_OS_VERSION_INT[
                        os_type].values():
                    constant.VIRTUAL_IO_OS_LIST.append(os_version)

    def _split_injected_files(self, injected_files):
        """FC plug in use injected_files impress custom info, split this

        :return:
        """
        customization = {}
        filtered_injected_files = []
        try:
            for (path, contents) in injected_files:
                if path == 'fc_customization':
                    for (key, values) in \
                            ast.literal_eval(contents).items():
                        customization[key] = values
                else:
                    filtered_injected_files.append([path, contents])
        except Exception as exc:
            utils.log_exception(exc)
            msg = _("Error dict object !")
            raise fc_exc.InvalidCustomizationInfo(reason=msg)
        return customization, filtered_injected_files

    def create_vm(self, context, instance, network_info, block_device_info,
                  image_meta, injected_files, admin_password, extra_specs):
        """Create VM on FC

        :param instance:
        :param network_info:
        :param image_meta:
        :param injected_files:
        :param admin_password:
        :param block_device_info:
        :return:
        """
        customization, filtered_injected_files = \
            self._split_injected_files(injected_files)

        # set qos io
        self._volume_ops.set_qos_specs_to_volume(block_device_info)

        # prepare network on FC
        LOG.debug(_('prepare network'))
        vifs = []
        for idx, network_item in enumerate(network_info):
            checksum_enable = False
            vif_profile = network_item.get('profile')
            if vif_profile:
                checksum = vif_profile.get('checksum_enable')
                if checksum:
                    if str(checksum).upper() == "TRUE":
                        checksum_enable = True
            pg_urn = self._network_ops.ensure_network(
                network_item['network'], checksum_enable, extra_specs)
            enable_dhcp = self._network_ops.\
                is_enable_dhcp(context, network_item['id'])
            vifs.append({
                'sequence_num': idx,
                'pg_urn': pg_urn,
                'enable_dhcp': enable_dhcp,
                'network_info': network_item
            })
        location = self._cluster_ops.\
            get_cluster_urn_by_nodename(instance['node'])

        # ensure instance group
        resource_group_urn = self.ensure_instance_group(
            instance, cluster_urn=location)
        # initial obj and create vm
        try:
            LOG.debug(_('begin create vm in fc.'))
            vm_create = vmcreation.get_vm_create(self.fc_client, self.task_ops,
                                                 instance, image_meta)
            vm_create(
                context,
                self._volume_ops,
                location,
                vifs,
                block_device_info,
                image_meta,
                filtered_injected_files,
                admin_password,
                extra_specs,
                customization,
                resource_group_urn,
                self)
            vm_create.create_and_boot_vm()
        except Exception as exc:
            utils.log_exception(exc)
            msg = _("create and boot vm %s failed.") % instance['uuid']
            self.delete_vm(
                context,
                instance,
                block_device_info,
                is_need_check_safe_format=False)
            raise exception.InstancePowerOnFailure(msg)

        boot_result = {'result': False}

        def _wait_for_boot():
            """Called at an interval until the VM is running."""

            statue = FC_MGR.get_vm_by_uuid(instance).status
            if statue == constant.VM_STATUS.RUNNING:
                LOG.debug(_("vm %s create success."), instance['uuid'])
                boot_result['result'] = True
                raise loopingcall.LoopingCallDone()
            elif statue == constant.VM_STATUS.STOPPED:
                LOG.error(_("create vm %s success, but start  failed."),
                          instance['uuid'])
                raise loopingcall.LoopingCallDone()
            else:
                LOG.info(_("vm %s is still in creating state."),
                         instance['uuid'])

        timer = loopingcall.FixedIntervalLoopingCall(_wait_for_boot)
        timer.start(interval=1).wait()

        if not boot_result['result']:
            self.delete_vm(
                context,
                instance,
                block_device_info,
                is_need_check_safe_format=False)
            msg = _("create vm %s success, but start failed.") % \
                instance['uuid']
            raise exception.InstancePowerOnFailure(msg)

        try:
            urn = FC_MGR.get_vm_by_uuid(instance).urn
            instance.system_metadata.update({'fc_vm_id': urn.split(':')[-1]})
            local_disk_property = self.get_local_disk_property(instance)
            if local_disk_property:
                instance.system_metadata.update(
                    {'local_disk_property': jsonutils.
                        dumps(local_disk_property)})
            instance.save()
        except Exception as exc:
            utils.log_exception(exc)
            LOG.warn(_("update sys metadata for %s failed."), instance['uuid'])

    def ensure_resource_group(self, cluster_urn, instance_group):

        resource_group = self._cluster_ops.get_resource_group(
            cluster_urn, instance_group)
        if resource_group:
            return resource_group.get('urn')
        else:
            try:
                return self._cluster_ops.create_resource_group(
                    cluster_urn, instance_group)
            except Exception as ex:
                # race condition
                resource_group = self._cluster_ops.get_resource_group(
                    cluster_urn, instance_group)
                if resource_group:
                    return resource_group.get('urn')
                else:
                    LOG.error("Create resource group "
                              "failed for %s .", instance_group['uuid'])
                    LOG.error("exception : ", ex)
                    raise ex

    def ensure_instance_group(self, instance, cluster_urn=None):
        instance_group = self.get_instance_group_by_instance_uuid(instance[
                                                                  'uuid'])
        if instance_group:
            if cluster_urn is None:
                cluster_urn = self._cluster_ops.\
                    get_cluster_urn_by_nodename(instance['node'])
            return self.ensure_resource_group(cluster_urn, instance_group)

    def get_instance_group_by_instance_uuid(
            self, instance_uuid, read_deleted='no'):
        """get_instance_group_by_instance_uuid

        get instance group info
        :param instance:
        :return:
        """
        inst_group = None
        try:
            inst_group = objects.InstanceGroup.get_by_instance_uuid(
                nova_context.get_admin_context(read_deleted=read_deleted),
                instance_uuid)
        except exception.InstanceGroupNotFound:
            LOG.debug(_("instance %s group not found."), instance_uuid)
            return inst_group
        return inst_group

    def cleanup_deleted_resource_group_by_instance(
            self, instance, cluster_urn=None):
        instance_group = self.get_instance_group_by_instance_uuid(
            instance['uuid'], read_deleted='only')
        if instance_group:
            if cluster_urn is None:
                cluster_urn = self._cluster_ops.\
                    get_cluster_urn_by_nodename(instance['node'])
            resource_group = self._cluster_ops.get_resource_group(
                cluster_urn, instance_group)
            if resource_group:
                self._cluster_ops.delete_resource_group(resource_group['urn'])

    @utils.timelimited(constant.CONF.fusioncompute.safe_stop_vm_timeout)
    def stop_vm_with_timelimited(self, instance, force=False):
        """Stop vm on FC

        :param instance:nova.objects.instance.Instance
        :return:
        """
        LOG.info(_("trying to stop vm: %s."), instance['uuid'])
        fc_vm = FC_MGR.get_vm_by_uuid(instance)
        if fc_vm.status == constant.VM_STATUS.STOPPED:
            LOG.info(_("vm has already stopped."))
            return
        elif force is True:
            body = {'mode': 'force'}
            LOG.info(_("force stop this vm."))
        else:
            body = {'mode': 'safe'}
            LOG.info(_("safe stop this vm."))
        try:
            self.post(fc_vm.get_vm_action_uri('stop'), data=body,
                      excp=exception.InstanceFaultRollback)
            return
        except Exception as ex:
            LOG.error("stop vm %s failed",
                instance['uuid'])
            LOG.error("reason is %s.", ex)
            raise exception.InstanceFaultRollback

    def stop_vm(self, instance, force=False):
        """Stop vm on FC

        :param instance:nova.objects.instance.Instance
        :return:
        """
        LOG.info(_("trying to stop vm: %s."), instance['uuid'])
        fc_vm = FC_MGR.get_vm_by_uuid(instance)
        if fc_vm.status == constant.VM_STATUS.STOPPED:
            LOG.info(_("vm has already stopped."))
            return
        elif force is True:
            body = {'mode': 'force'}
            LOG.info(_("force stop this vm."))
        else:
            body = {'mode': 'safe'}
            LOG.info(_("safe stop this vm."))
            try:
                self.post(fc_vm.get_vm_action_uri('stop'), data=body,
                          excp=exception.InstancePowerOffFailure)
                return
            except exception.InstancePowerOffFailure:
                LOG.error(
                    _("first stop vm %s failed, will force stop."),
                    instance['uuid'])
            # if first stop failed, force stop
            body = {'mode': 'force'}
        try:
            self.post(fc_vm.get_vm_action_uri('stop'), data=body,
                      excp=exception.InstanceFaultRollback)
            return
        except Exception as ex:
            LOG.error("stop vm %s failed, reason is %s.", instance['uuid'])
            raise exception.InstanceFaultRollback
        LOG.info(_("stop vm %s success"), instance['uuid'])

    def get_local_disk_property(self, instance):
        if instance.system_metadata.get('local_disk_property'):
            return jsonutils.loads(
                instance.system_metadata.get('local_disk_property'))
        result = {}
        extra_specs = self.get_instance_extra_specs(instance)
        if extra_specs:
            local_disk_property = extra_specs.get('quota:local_disk')
            if local_disk_property:
                local_disk_property = local_disk_property.split(':')
                result['type'] = local_disk_property[0]
                result['count'] = int(local_disk_property[1])
                result['size'] = int(local_disk_property[2])
                result['safe_format'] = local_disk_property[3]
        if len(result) == 4:
            return result

    def delete_local_disk(self, disk_urns):
        deleted_disk_urns = []
        delete_failed_disk_urns = []
        if disk_urns:
            for disk_urn in disk_urns:
                uri = utils.generate_uri_from_urn(disk_urn)
                try:
                    self._volume_ops.delete_volume(uri)
                    deleted_disk_urns.append(disk_urn)
                except Exception:
                    delete_failed_disk_urns.append(disk_urn)
        return deleted_disk_urns, delete_failed_disk_urns

    def _modify_boot_option_if_needed(self, instance, fc_vm):
        """_modify_boot_option_if_needed

        :param instance: OpenStack instance object
        :param fc_vm: FusionCompute vm object
        :return:
        """

        new_boot_option = utils.get_boot_option_from_metadata(
            instance.get('metadata'))

        old_boot_option = None
        if 'vmConfig' in fc_vm:
            vm_property = fc_vm['vmConfig'].get('properties')
            old_boot_option = vm_property.get('bootOption') if vm_property \
                else None

        if new_boot_option and old_boot_option and \
           new_boot_option != old_boot_option:
            body = {
                'properties': {
                    'bootOption': new_boot_option
                }
            }
            try:
                self.modify_vm(instance, vm_config=body)
            except Exception as msg:
                LOG.error(_("modify boot option has exception: %s") % msg)

    def _modify_vnc_keymap_setting_if_needed(self, instance, fc_vm):
        """_modify_vnc_keymap_setting_if_needed

        :param instance: OpenStack instance object
        :param fc_vm: FusionCompute vm object
        :return:
        """
        new_vnc_keymap_setting = utils.get_vnc_key_map_setting_from_metadata(
            instance.get('metadata'))

        old_vnc_keymap_setting = None
        if 'vmConfig' in fc_vm:
            vm_property = fc_vm['vmConfig'].get('properties')
            old_vnc_keymap_setting = vm_property.get(
                'vmVncKeymapSetting') if vm_property else None

        if new_vnc_keymap_setting and old_vnc_keymap_setting and \
           new_vnc_keymap_setting != old_vnc_keymap_setting:
            body = {
                'properties': {
                    'vmVncKeymapSetting': new_vnc_keymap_setting
                }
            }
            try:
                self.modify_vm(instance, vm_config=body)
            except Exception as msg:
                LOG.error(
                    _("modify vnc_keymap setting has exception: %s") %
                    msg)

    def change_instance_metadata(self, instance):
        """change_instance_metadata

        :param instance:
        :return:
        """
        LOG.info(_("trying to change metadata for vm: %s.") % instance['uuid'])

        try:
            fc_vm = FC_MGR.get_vm_by_uuid(instance)
            self._modify_boot_option_if_needed(instance, fc_vm)
            self._modify_vnc_keymap_setting_if_needed(instance, fc_vm)
        # ignore pylint:disable=W0703
        except Exception as msg:
            LOG.error(_("change_instance_metadata has exception, msg = %s")
                      % msg)

    def change_instance_info(self, instance):

        LOG.info(_("trying to change instance display_name = %s"),
                 instance['display_name'])

        body = {'name': instance['display_name']}
        try:
            self.modify_vm(instance, vm_config=body)
        except Exception as msg:
            LOG.error(_("change_instance_info has exception, msg = %s")
                      % msg)

    def get_instance_extra_specs(self, instance):
        """get instance extra info

        :param instance:
        :return:
        """
        # ignore pylint:disable=E1101
        inst_type = objects.Flavor.get_by_id(
            nova_context.get_admin_context(read_deleted='yes'),
            instance['instance_type_id'])
        return inst_type.get('extra_specs', {})

    def start_vm(self, instance, block_device_info=None):
        """Start vm on FC

        :param instance:nova.objects.instance.Instance
        :return:
        """
        LOG.info(_("trying to start vm: %s.") % instance['uuid'])

        self.cleanup_deleted_resource_group_by_instance(instance)

        fc_vm = FC_MGR.get_vm_by_uuid(instance)
        if fc_vm.status in [constant.VM_STATUS.STOPPED,
                            constant.VM_STATUS.SUSPENDED]:
            self._modify_boot_option_if_needed(instance, fc_vm)
            try:
                self.post(fc_vm.get_vm_action_uri('start'),
                          excp=exception.InstancePowerOnFailure)
            except Exception as ex:
                LOG.error(ex)
                reason = _("FusionCompute start vm %s failed") % instance[
                    'uuid']
                raise exception.InstancePowerOnFailure(reason)
            LOG.info(_("start vm %s success"), instance['uuid'])
        elif fc_vm.status == constant.VM_STATUS.RUNNING:
            LOG.info(_("vm has already running."))
        else:
            reason = _("vm status is %s and cannot be powered on.") % \
                fc_vm.status
            raise exception.InstancePowerOnFailure(reason=reason)

    def create_and_attach_local_disk_before_start(
            self, instance, block_device_info):

        local_disk_property = self.get_local_disk_property(instance)
        if local_disk_property:
            fc_vm = FC_MGR.get_vm_by_uuid(instance)
            cluster_urn = self._cluster_ops.\
                get_cluster_urn_by_nodename(instance['node'])

            cinder_volume_urns = self._get_vol_urns_from_block_device_info(
                block_device_info)

            volume_urns = self._volume_ops.create_local_disk_batch(
                cluster_urn=cluster_urn,
                volume_urns=cinder_volume_urns,
                local_disk_type=local_disk_property.get('type'),
                local_disk_count=local_disk_property.get('count'),
                local_disk_size=local_disk_property.get('size'),
                fc_vm_urn=fc_vm.urn,
                local_disk_safe_format=local_disk_property.get('safe_format'))
            unbind_volume_urns = self.attach_local_disk_batch(
                volume_urns, fc_vm)
            if unbind_volume_urns is not None and len(unbind_volume_urns) > 0:
                self.delete_local_disk(unbind_volume_urns)
                reason = _(
                    "vm %s need to attach local disk before"
                    " power on but failed.") % fc_vm.uuid
                raise exception.InstancePowerOnFailure(reason=reason)

    def _get_vol_urns_from_block_device_info(self, block_device_info):
        vol_urns = []
        if block_device_info and block_device_info.get('block_device_mapping'):
            LOG.info(
                _('create local disk block device info is %s.'),
                str(block_device_info))
            for vol in block_device_info.get('block_device_mapping'):
                vol_urn = self._get_vol_urn_from_connection(
                    vol.get('connection_info'))
                vol_urns.append(vol_urn)
        return vol_urns

    def attach_local_disk_batch(self, volume_urns, fc_vm):
        bind_volume_urns = []
        sequenct_num = 1
        for volume_urn in volume_urns:
            try:
                sequenct_num = self.get_sequence_num_local_disk(sequenct_num)
                body = {
                    'volUrn': volume_urn,
                    'sequenceNum': sequenct_num
                }
                self._volume_ops.attach_volume(fc_vm, vol_config=body)
                bind_volume_urns.append(volume_urn)
            except Exception:
                LOG.error(_('bind local disk to vm failed.'))
                break
        return set(volume_urns) - set(bind_volume_urns)

    def get_sequence_num_local_disk(self, last_sequence_num):

        if constant.CONF.fusioncompute.reserve_disk_symbol is None or str(
                constant.CONF.fusioncompute.reserve_disk_symbol).upper() \
                == 'TRUE':
            return last_sequence_num + 1
        else:
            if last_sequence_num == 1:
                return 1001
            elif last_sequence_num == 1003:
                return 2
            elif last_sequence_num == 22:
                return 1004
            elif last_sequence_num == 1004:
                return 23
            else:
                return last_sequence_num + 1

    def get_sequence_nums_local_disk(self, count):

        sequence_nums_local_disk = []
        sequence_num = 1
        for i in range(count):
            sequence_num = self.get_sequence_num_local_disk(sequence_num)
            sequence_nums_local_disk.append(sequence_num)
        return sequence_nums_local_disk

    def _reboot_vm(self, fc_vm, reboot_type):
        """reboot vm inner func"""
        body = {'mode': constant.FC_REBOOT_TYPE[reboot_type]}
        self.post(fc_vm.get_vm_action_uri('reboot'), data=body,
                  excp=exception.InstanceRebootFailure)
        LOG.debug(_("_reboot_vm %s success"), fc_vm.uuid)

    def reboot_vm(self, instance, reboot_type, block_device_info):
        """reboot vm"""
        fc_vm = FC_MGR.get_vm_by_uuid(instance)

        # if it is fault-resuming or unknown, do nothing
        if fc_vm.status == constant.VM_STATUS.UNKNOWN \
                or fc_vm.status == constant.VM_STATUS.FAULTRESUMING \
                or fc_vm.status == constant.VM_STATUS.MIGRATING:
            LOG.debug(_("vm %s status is fault-resuming or unknown "
                        "or migrating, just ignore this reboot action."),
                      instance['uuid'])
            return

        # if it is stopped or suspended, just start it
        if fc_vm.status == constant.VM_STATUS.STOPPED \
                or fc_vm.status == constant.VM_STATUS.SUSPENDED:
            LOG.debug(_("vm %s is stopped, will start vm."), instance['uuid'])
            self.start_vm(instance, block_device_info)
            return

        # if it is paused, first unpause it
        if fc_vm.status == constant.VM_STATUS.PAUSED:
            self.unpause_vm(instance)

        # modify vm boot type if needed
        self._modify_boot_option_if_needed(instance, fc_vm)

        if reboot_type == constant.REBOOT_TYPE.SOFT:
            try:
                self._reboot_vm(fc_vm, reboot_type)
                return
            except exception.InstanceRebootFailure:
                LOG.debug(_("soft reboot vm %s failed, will hard reboot."),
                          instance['uuid'])

        # if soft reboot failed, hard reboot
        self._reboot_vm(fc_vm, constant.REBOOT_TYPE.HARD)

    def pause_vm(self, instance):
        """Pause vm on FC

        :param instance:nova.objects.instance.Instance
        :return:
        """
        LOG.info(_("trying to pause vm: %s.") % instance['uuid'])

        if self.get_local_disk_property(instance):
            reason = _("vm %s can not be resized due to "
                       "it has local disk.") % instance['uuid']
            raise fc_exc.InstancePauseFailure(reason=reason)

        fc_vm = FC_MGR.get_vm_by_uuid(instance)
        if fc_vm.status == constant.VM_STATUS.RUNNING:
            self.post(fc_vm.get_vm_action_uri('pause'),
                      excp=fc_exc.InstancePauseFailure)
            LOG.info(_("pause vm %s success"), instance['uuid'])
        elif fc_vm.status == constant.VM_STATUS.PAUSED:
            LOG.info(_("vm status is paused, consider it success."))
        else:
            reason = _("vm status is %s and cannot be paused.") % fc_vm.status
            raise fc_exc.InstancePauseFailure(reason=reason)

    def unpause_vm(self, instance):
        """Unpause vm on FC

        :param instance:nova.objects.instance.Instance
        :return:
        """
        LOG.info(_("trying to unpause vm: %s."), instance['uuid'])
        fc_vm = FC_MGR.get_vm_by_uuid(instance)
        if fc_vm.status == constant.VM_STATUS.PAUSED:
            self.post(fc_vm.get_vm_action_uri('unpause'),
                      excp=fc_exc.InstanceUnpauseFailure)
            LOG.info(_("unpause vm %s success"), instance['uuid'])
        elif fc_vm.status == constant.VM_STATUS.RUNNING:
            LOG.info(_("vm status is running, consider it success"))
        else:
            reason = _("vm status is %s and cannot be unpaused.") % \
                fc_vm.status
            raise fc_exc.InstanceUnpauseFailure(reason=reason)

    def suspend_vm(self, instance):
        """suspend vm on FC

        :param instance:nova.objects.instance.Instance
        :return:
        """

        LOG.info(_("trying to suspend vm: %s."), instance['uuid'])
        fc_vm = FC_MGR.get_vm_by_uuid(instance)
        if fc_vm.status == constant.VM_STATUS.RUNNING:
            try:
                self.post(fc_vm.get_vm_action_uri('suspend'),
                          excp=exception.InstanceFaultRollback)
            except Exception as ex:
                LOG.error(
                    _("Fc_vm is running ,but suspending vm is error."
                      "The reason is %s.") %
                    ex)
                raise exception.InstanceFaultRollback
            LOG.info(_("suspend vm %s success"), instance['uuid'])
        else:
            LOG.error(_("error vm status: %s.") % fc_vm.status)
            raise exception.InstanceFaultRollback

    def _delete_vm_with_fc_vm(
            self,
            instance,
            destroy_disks=True,
            is_need_check_safe_format=True):
        """delete vm with fc instance, inner function

        :param fc_vm:
        :param destroy_disks:
        :return:
        """
        @nova_utils.synchronized(INSTANCES_ACTION_SEMAPHORE % instance.uuid)
        def _delete_vm():

            @utils.timelimited(constant.CONF.fusioncompute.
                               fc_request_timeout_delete_vm_timelimited)
            def _delete_vm_with_timelimited():
                fc_vm = FC_MGR.get_vm_by_uuid(instance)
                local_disk_property = self.get_local_disk_property(instance)
                local_disk_count = 0
                if local_disk_property:
                    local_disk_count = local_disk_property.get('count')
                local_disk_sequence_nums = self.get_sequence_nums_local_disk(
                    local_disk_count)
                try:
                    for disk in fc_vm['vmConfig']['disks']:
                        if disk['sequenceNum'] > 1 and disk[
                                'sequenceNum'] not in local_disk_sequence_nums:
                            LOG.info(
                                _('Detach leaked volume: %s'),
                                disk['volumeUrn'])
                            connection_info = {'vol_urn': disk['volumeUrn']}
                            self.detach_volume(connection_info, instance)
                except Exception as e:
                    LOG.warn(_('Detach other volumes failed for: %s'), e)

                reserve_disks = {'isReserveDisks': 0 if destroy_disks else 1}
                if destroy_disks and is_need_check_safe_format is True:
                    reserve_disks[
                        'isFormat'] = self._is_disk_safe_format(instance)
                self.delete(
                    utils.build_uri_with_params(
                        fc_vm.uri, reserve_disks))

            _delete_vm_with_timelimited()

        _delete_vm()

    def _is_disk_safe_format(self, instance):

        instance_metadata = instance.get('metadata')
        if instance_metadata:
            safe_format = instance_metadata.get('__local_disk_safe_format')
            if safe_format and str(safe_format).upper() == 'TRUE':
                return 1  # safe format
            elif safe_format and str(safe_format).upper() == 'FALSE':
                return 0  # not safe format
        local_disk_property = self.get_local_disk_property(instance)
        if local_disk_property:
            safe_format = local_disk_property.get('safe_format')
            if safe_format and str(safe_format).upper() == 'FALSE':
                return 0
            else:
                return 1
        return 0

    def _update_affinity_groups(self, context, instance):
        """_update_affinity_groups

        :param context:
        :param instance:
        :return:
        """

    def _update_drs_rules(self, instance):
        """_update_drs_rules

        :param instance:
        :return:
        """

        node = instance.get('node')
        if node is None:
            LOG.error(_('failed to get node info from instance'))
            return

        cluster = self._cluster_ops.get_cluster_detail_by_nodename(node)
        if cluster is None:
            LOG.error(_('failed to get cluster info by node: %s'), node)
            return

        drs_rules = cluster['drsSetting']['drsRules']
        for drs_rule in drs_rules:
            if len(drs_rule['vms']) < 2:
                rule_name = str(drs_rule['ruleName'])
                rule_type = drs_rule['ruleType']
                self._cluster_ops.\
                    delete_drs_rules(cluster, rule_name, rule_type)

    @utils.timelimited(
        constant.CONF.fusioncompute.fc_request_timeout_delete_vm)
    def delete_vm(self, context, instance, block_device_info=None,
                  destroy_disks=True, is_need_check_safe_format=True):
        """Delete VM on FC

        :param context:
        :param instance:
        :param block_device_info:
        :param destroy_disks:
        :param is_need_check_safe_format:
        :return:
        """

        # if revert resize, only stop vm. when resize operation
        # task state will be resize_reverting or resize_confirming
        if instance and (instance.get('task_state') == 'resize_reverting'
                         or instance.get('task_state') == 'resize_confirming'):
            LOG.info(_('revert resize now, here only stop vm.'))
            try:
                self.stop_vm(instance)
            except Exception as e:
                LOG.warn(
                    _('safe stop vm failed, trigger force stop vm. %s'), e)
                try:
                    self.stop_vm(instance, force=True)
                except Exception as ex:
                    LOG.warn(_('stop vm failed, trigger rollback'))
                    raise exception.InstanceFaultRollback(inner_exception=ex)
            return

        try:
            fc_vm = FC_MGR.get_vm_by_uuid(instance)
        except exception.InstanceNotFound:
            LOG.warn(_('instance exist no more. ignore this deleting.'))
            return

        # if vm is in fault-resuming or unknown status, can not do delete
        if fc_vm.status == constant.VM_STATUS.UNKNOWN \
                or fc_vm.status == constant.VM_STATUS.FAULTRESUMING:
            LOG.warn(_("Vm %s status is fault-resuming or unknown, "
                       "stop this deletion !"), instance['uuid'])
            msg = 'Vm status is fault-resuming or unknown, can not be delete'
            raise exception.InstancePowerOffFailure(message=msg)

        # detach volume created by cinder
        if block_device_info:
            LOG.info(_('now will stop vm before detach cinder volumes.'))
            self.stop_vm(instance, force=True)
            for vol in block_device_info['block_device_mapping']:
                self.detach_volume(vol['connection_info'], instance,
                                   is_snapshot_del=False)

        self._delete_vm_with_fc_vm(
            instance, destroy_disks, is_need_check_safe_format)

        # update affinity group info if needed
        try:
            # self._update_drs_rules(instance)
            self._update_affinity_groups(context, instance)
        # ignore pylint:disable=W0703
        except Exception as excp:
            utils.log_exception(excp)
            LOG.error(_('update affinity group info failed !'))

    def clone_vm(self, instance, vm_config=None):
        """Clone vn in FC

        :param instance:
        :param vm_config:
        :return:
        """
        fc_vm = FC_MGR.get_vm_by_uuid(instance)
        return self.post(fc_vm.get_vm_action_uri('clone'), data=vm_config,
                         excp=fc_exc.InstanceCloneFailure)

    def modify_vm(self, instance, vm_config=None):
        """Modify vm config in FC

        :param instance:
        :param vm_config:
        :return:
        """
        fc_vm = FC_MGR.get_vm_by_uuid(instance)
        self.put(fc_vm.uri, data=vm_config, excp=fc_exc.InstanceModifyFailure)

    def _find_destination_node(self, context, instance, host):
        """_find_destination_node

        Call scheduler api
        :param context:
        :param instance:
        :param host:
        :return:
        """

        def _build_request_spec():
            request_spec = {
                'image': {},
                'instance_properties': instance,
                'instance_type': instance.flavor,
                'num_instances': 1,
                'instance_uuids': [instance['uuid']]}
            return jsonutils.to_primitive(request_spec)

        try:
            filter_properties = {'force_hosts': host}
            nodename = self.scheduler_client.select_destinations(
                context, _build_request_spec(),
                filter_properties)[0]['nodename']
        except Exception as e:
            LOG.error("Select node from host %(host)s failed because: %(e)s",
                      {"host": host, "e": e})
            raise exception.NodeNotFound
        return nodename

    def live_migration(self, context, instance, hostname, post_method,
                       recover_method, block_migration, migrate_data):
        """live_migration

        :param context:
        :param instance:
        :param hostname:
        :param post_method:
        :param recover_method:
        :param block_migration:
        :param migrate_data:
        :return:
        """

        try:

            # get destination from scheduler
            nodename = self._find_destination_node(context, instance, hostname)
            LOG.debug(_("Scheduler choose %s as destination node."), nodename)

            # get destination cluster urn
            cluster_urn = self._cluster_ops.get_cluster_urn_for_migrate(
                nodename)
            if not cluster_urn:
                raise fc_exc.ClusterNotFound(cluster_name=nodename)

            if self.get_local_disk_property(instance):
                LOG.error(
                    _("vm %s can not be live migrated due to it has "
                      "local disk."),
                    instance['uuid'])
                raise exception.MigrationError

            self.cleanup_deleted_resource_group_by_instance(
                instance, cluster_urn=cluster_urn)

            resource_group_urn = self.ensure_instance_group(
                instance, cluster_urn=cluster_urn)

            # generate migrate url and post msg to FC
            body = {
                'location': cluster_urn
            }
            if resource_group_urn:
                body['resourceGroup'] = resource_group_urn
            fc_vm = FC_MGR.get_vm_by_uuid(instance)
            self.post(fc_vm.get_vm_action_uri('migrate'), data=body,
                      excp=exception.MigrationError)
            post_method(
                context,
                instance,
                hostname,
                block_migration,
                migrate_data)
            LOG.info(_("Live Migration success: %s"), instance['uuid'])
        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.error(
                    _("Live Migration failure: %s"),
                    e,
                    instance=instance)
                recover_method(context, instance, hostname, block_migration)

    def post_live_migration_at_destination(self, instance):
        try:
            fc_vm = FC_MGR.get_vm_by_uuid(instance)
            node_name = self._cluster_ops.create_nodename(fc_vm['clusterName'])
            instance.node = node_name
            instance.save()
            LOG.warn(_("Modify node name for %s success"), instance.uuid)
        except Exception as e:
            LOG.warn(_("Modify node name failed after migration: %s"), e)

    def migrate_disk_and_power_off(
            self,
            instance,
            dest,
            flavor,
            block_device_info):
        """modify the vm spec info

        :param instance:
            nova.db.sqlalchemy.models.Instance object
            instance object that is migrated.
        :param flavor:
        :return:
        """
        # if cluster's vcpus is 0 ,rolleback
        if dest:
            dest_cluster = dest[dest.rfind('@') + 1:]
            cluster_detail = self._cluster_ops.\
                get_cluster_resource(dest_cluster)
            if not cluster_detail['cpu_info']['pcpus']:
                LOG.error(_("The dest node %s's pcpus is 0"), dest_cluster)
                raise exception.InstanceFaultRollback

        fc_vm = FC_MGR.get_vm_by_uuid(instance)
        if fc_vm.status == constant.VM_STATUS.UNKNOWN \
                or fc_vm.status == constant.VM_STATUS.FAULTRESUMING:
            LOG.debug(_("vm %s status is fault-resuming or unknown, "
                        "can not do migrate or resize."), instance['uuid'])
            raise exception.InstanceFaultRollback

        if self.get_local_disk_property(instance):
            LOG.error(
                _("vm %s can not be resized due to it has local disk."),
                instance['uuid'])
            raise exception.InstanceFaultRollback

        LOG.info(_("begin power off vm ..."))

        # 1.stop vm
        self.stop_vm(instance)

        # 2.save flavor and vol info in vm
        fc_vm = FC_MGR.get_vm_by_uuid(instance)
        old_flavor = self._gen_old_flavor_for_fc(fc_vm)
        new_flavor = self._gen_new_flavor_for_fc(flavor)
        flavor = {
            'old_flavor': old_flavor,
            'new_flavor': new_flavor
        }
        data = {
            'group': '%s:%s' % (constant.VM_GROUP_FLAG,
                                jsonutils.dumps(flavor))
        }
        self.modify_vm(fc_vm, vm_config=data)
        LOG.info(_("save flavor info success."))

        # 3. check cpu mem changes
        flavor = None
        if self._check_if_need_modify_vm_spec(old_flavor, new_flavor):
            flavor = new_flavor

        data = self._generate_vm_spec_info(flavor=flavor)

        # modify secureVmType
        if old_flavor.get('secureVmType') != new_flavor.get('secureVmType'):
            data['properties'] = {
                'secureVmType': new_flavor.get('secureVmType', '')
            }
        # check vgpu params
        if old_flavor.get('gpu_num') != new_flavor.get('gpu_num') \
                or old_flavor.get('gpu_mode') != \
                        snew_flavor.get('gpu_mode'):
            try:
                self.modify_vm_gpu(fc_vm, old_flavor, new_flavor)
            except Exception as ex:
                if instance.system_metadata.get('old_vm_state') == 'active':
                    try:
                        self.start_vm(instance, block_device_info)
                    except Exception as e3:
                        LOG.error(_("try start vm failed: %s"), e3)
                raise ex

        # check enhanced network params
        try:
            self.modify_instance_vnic(fc_vm, old_flavor, new_flavor)
        except Exception as ex:
            try:
                if old_flavor.get('gpu_num') != new_flavor.get('gpu_num') \
                        or old_flavor.get('gpu_mode') != \
                                new_flavor.get('gpu_mode'):
                    self.modify_vm_gpu(fc_vm, new_flavor, old_flavor)
            except Exception as e2:
                LOG.error(_("roll back vgpu failed: %s"), e2)
            if instance.system_metadata.get('old_vm_state') == 'active':
                try:
                    self.start_vm(instance, block_device_info)
                except Exception as e3:
                    LOG.error(_("try start vm failed: %s"), e3)
            raise ex

        try:
            self.modify_vm(fc_vm, vm_config=data)
        except Exception as e:
            try:
                self.modify_instance_vnic(fc_vm, new_flavor, old_flavor)
            except Exception as e1:
                LOG.error(_("rollback instance_vnic failed: %s"), e1)
            try:
                if old_flavor.get('gpu_num') != new_flavor.get('gpu_num') \
                        or old_flavor.get('gpu_mode') != new_flavor.get('gpu_mode'):
                    self.modify_vm_gpu(fc_vm, new_flavor, old_flavor)
            except Exception as e2:
                LOG.error(_("roll back vgpu failed: %s"), e2)
            if instance.system_metadata.get('old_vm_state') == 'active':
                try:
                    self.start_vm(instance, block_device_info)
                except Exception as e3:
                    LOG.error(_("try start vm failed: %s"), e3)
            raise e
        LOG.info(_("modify cpu and mem success."))

    def _get_flavor_from_group(self, group):
        """_get_flavor_from_group

        :param group:
        :return:
        """

        if not isinstance(group, str):
            group = str(group)

        flavor = ast.literal_eval(group[group.find(':') + 1:])
        return flavor['old_flavor'], flavor['new_flavor']

    def finish_migration(
            self,
            instance,
            power_on=True,
            block_device_info=None):
        """finish_migration

        :param instance:
        :param power_on:
        :return:
        """
        LOG.info(_("begin finish_migration ..."))

        fc_vm = FC_MGR.get_vm_by_uuid(instance)
        # update location
        location = self._cluster_ops.\
            get_cluster_urn_by_nodename(instance['node'])

        self.cleanup_deleted_resource_group_by_instance(
            instance, cluster_urn=location)

        # create resource group before migrate
        resource_group_urn = self.ensure_instance_group(
            instance, cluster_urn=location)

        # update location
        data = self._generate_vm_spec_info(location=location)
        if resource_group_urn:
            data['resourceGroup'] = resource_group_urn

        self.modify_vm(fc_vm, vm_config=data)

        # power on vm if needed
        if power_on:
            self.start_vm(instance, block_device_info)

        LOG.info(_("modify location success, new location %s."), location)

    def _reset_vm_group(self, fc_vm):
        """_reset_vm_group

        :param fc_vm:
        :return:
        """

        data = {
            'group': constant.VM_GROUP_FLAG
        }
        self.modify_vm(fc_vm, vm_config=data)

    def finish_revert_migration(
            self,
            instance,
            power_on=True,
            block_device_info=None):
        """finish_revert_migration

        :param instance:
        :param power_on:
        :return:
        """

        LOG.info(_("begin finish_revert_migration ..."))

        # 1. get flavor info from fc
        fc_vm = FC_MGR.get_vm_by_uuid(instance)
        # ignore pylint:disable=W0612
        old_flavor, new_flavor = self._get_flavor_from_group(fc_vm.group)

        # 2. check cpu mem changes
        location = self._cluster_ops.\
            get_cluster_urn_by_nodename(instance['node'])

        self.cleanup_deleted_resource_group_by_instance(
            instance, cluster_urn=location)
        resource_group_urn = self.ensure_instance_group(
            instance, cluster_urn=location)

        # 3. check vgpu params
        if old_flavor.get('gpu_num') != new_flavor.get('gpu_num') \
                or old_flavor.get('gpu_mode') != new_flavor.get('gpu_mode'):
            self.modify_vm_gpu(fc_vm, new_flavor, old_flavor)

        data = self._generate_vm_spec_info(location=location,
                                           flavor=old_flavor)
        if resource_group_urn:
            data['resourceGroup'] = resource_group_urn

        # modify secureVmType
        if old_flavor.get('secureVmType') != new_flavor.get('secureVmType'):
            data['properties'] = {
                'secureVmType': old_flavor.get('secureVmType', '')
            }
        self.modify_vm(fc_vm, vm_config=data)
        LOG.info(_("modify cpu and mem success."))

        # 4. check enhanced network params
        self.modify_instance_vnic(fc_vm, new_flavor, old_flavor)

        # 5. clear vm group info
        self._reset_vm_group(fc_vm)

        # 6. power on vm if needed
        if power_on:
            self.start_vm(instance, block_device_info)

    def modify_instance_vnic(self, fc_vm, old_flavor, new_flavor):
        if old_flavor.get('instance_bandwidth') != new_flavor.\
                get('instance_bandwidth') \
                or old_flavor.get('instance_max_vnic') != new_flavor.\
                        get('instance_max_vnic'):
            uri = fc_vm.uri + '/simplespec'
            body = {
                'vmParams': {
                    'bandwidth': new_flavor.get('instance_bandwidth'),
                    'maxVnic': new_flavor.get('instance_max_vnic')}}
            self.put(uri, data=body, excp=fc_exc.InstanceModifyFailure)

    def modify_vm_gpu(self, fc_vm, src_flavor, dest_flavor):

        src_gpu_num = src_flavor.get(
            'gpu_num') if src_flavor.get('gpu_num') else 0
        src_gpu_mode = src_flavor.get('gpu_mode')
        dest_gpu_num = dest_flavor.get(
            'gpu_num') if dest_flavor.get('gpu_num') else 0
        dest_gpu_mode = dest_flavor.get('gpu_mode')
        attach_gpu_uri = fc_vm.get_vm_action_uri('attach_gpu')
        detach_gpu_uri = fc_vm.get_vm_action_uri('detach_gpu')

        if src_gpu_mode is not None and dest_gpu_mode is not None \
                and src_gpu_mode != dest_gpu_mode:
            for i in range(src_gpu_num):
                self.post(detach_gpu_uri, data={'gpuUrn': 'auto'},
                          excp=fc_exc.InstanceModifyFailure)
            src_gpu_num = 0

        if src_gpu_num > dest_gpu_num:
            for i in range(src_gpu_num - dest_gpu_num):
                self.post(detach_gpu_uri, data={'gpuUrn': 'auto'},
                          excp=fc_exc.InstanceModifyFailure)
        elif src_gpu_num < dest_gpu_num:
            memory_quantity = fc_vm['vmConfig']['memory']['quantityMB']
            memory_reservation = fc_vm['vmConfig']['memory']['reservation']
            if memory_quantity != memory_reservation:
                data = {'memory': {
                    'quantityMB': memory_quantity,
                    'reservation': memory_quantity
                }}
                # vm must reserve all memory while vm has gpu
                self.modify_vm(fc_vm, vm_config=data)
            for i in range(dest_gpu_num - src_gpu_num):
                self.post(
                    attach_gpu_uri,
                    data={
                        'gpuUrn': 'auto',
                        'mode': dest_gpu_mode},
                    excp=fc_exc.InstanceModifyFailure)

    def confirm_migration(self, instance):
        """confirm_migration

        :param instance:
        :return:
        """

        LOG.info(_("begin confirm_migration ..."))

        # clear vm group info
        fc_vm = FC_MGR.get_vm_by_uuid(instance)
        self._reset_vm_group(fc_vm)

    def _check_if_need_modify_vm_spec(self, old_flavor, new_flavor):
        """_check_if_need_modify_vm_spec

        Check if it is need to modify vm spec
        :param old_flavor:
        :param new_flavor:
        :return:
        """

        if not old_flavor or not new_flavor:
            return False

        old_quantity = old_flavor.get('vcpus', None)
        old_mem = old_flavor.get('memory_mb', None)
        old_reservation = old_flavor.get('reservation', None)
        old_weight = old_flavor.get('weight', None)
        old_limit = old_flavor.get('limit', None)
        old_socketnum = old_flavor.get('socketNum', None)
        old_instance_bandwidth = old_flavor.get('instance_bindwidth')
        old_instance_max_vnic = old_flavor.get('instance_max_vnic')
        old_gpu_num = old_flavor.get('gpu_num')
        old_gpu_mode = old_flavor.get('gpu_mode')
        old_secure_vm_type = old_flavor.get('secureVmType')

        new_quantity = new_flavor.get('vcpus', None)
        new_mem = new_flavor.get('memory_mb', None)
        new_reservation = new_flavor.get('reservation', None)
        new_weight = new_flavor.get('weight', None)
        new_limit = new_flavor.get('limit', None)
        new_socketnum = new_flavor.get('socketNum', None)
        new_instance_bandwidth = new_flavor.get('instance_bindwidth')
        new_instance_max_vnic = new_flavor.get('instance_max_vnic')
        new_gpu_num = new_flavor.get('gpu_num')
        new_gpu_mode = new_flavor.get('gpu_mode')
        new_secure_vm_type = new_flavor.get('secureVmType')

        if (old_quantity != new_quantity) \
                or (old_mem != new_mem) \
                or (old_reservation != new_reservation) \
                or (old_weight != new_weight) \
                or (old_limit != new_limit) \
                or (old_socketnum != new_socketnum) \
                or (old_gpu_num != new_gpu_num) \
                or (old_instance_bandwidth != new_instance_bandwidth) \
                or (old_instance_max_vnic != new_instance_max_vnic)\
                or (old_gpu_mode != new_gpu_mode)\
                or (old_secure_vm_type != new_secure_vm_type):
            return True

        return False

    def _get_sys_vol_from_vm_info(self, instance):
        """_get_sys_vol_from_vm_info

        Get sys volume info from instance info
        :param instance:
        :return:
        """

        if not instance:
            return None

        for disk in instance['vmConfig']['disks']:
            if 1 == disk['sequenceNum']:
                return disk
        return None

    def _generate_vm_spec_info(self, location=None, flavor=None):
        """_generate_vm_spec_info

        Generate the vm spec info for cole migration
        :param location:
        :param flavor:
        :return:
        """

        data = {}
        if location:
            data['location'] = location
        if flavor:
            if flavor.get('vcpus'):
                data['cpu'] = {
                    'quantity': flavor.get('vcpus')
                }
                numa_nodes = flavor.get('socketNum', None)
                if numa_nodes is not None:
                    _core_per_socket = int(
                        flavor.get('vcpus')) / int(numa_nodes)
                    data['cpu'].update({'coresPerSocket': _core_per_socket})

            if flavor.get('memory_mb'):
                data['memory'] = {
                    'quantityMB': flavor.get('memory_mb')
                }
                # vm must reserve all memory while vm has gpu
                if flavor.get('gpu_num') > 0:
                    data['memory'].update(
                        {'reservation': flavor.get('memory_mb')})

            cpu_qos = utils.fc_qos_convert(
                flavor,
                constant.CPU_QOS_FC_KEY,
                constant.CPU_QOS_FC_KEY,
                flavor.get('vcpus'))
            if data.get('cpu', None):
                data['cpu'] = utils.dict_add(data['cpu'], cpu_qos)
            else:
                data['cpu'] = cpu_qos

        LOG.debug(_("vm spec data: %s.") % jsonutils.dumps(data))
        return data

    def _get_sys_vol_info(self, sys_vol):
        """_get_sys_vol_info

        :param sys_vol:
        :return:
        """
        return {
            'volUrn': sys_vol['volumeUrn'],
            'pciType': sys_vol['pciType'],
            'sequenceNum': 1
        }

    def _gen_old_flavor_for_fc(self, instance):
        """_gen_old_flavor_for_fc

        :param instance:
        :return:
        """
        coresPerSocket = instance['vmConfig']['cpu']['coresPerSocket']
        vcpus = instance['vmConfig']['cpu']['quantity']

        flavor_dict = {
            'vcpus': vcpus,
            'memory_mb': instance['vmConfig']['memory']['quantityMB'],
            'socketNum': vcpus / coresPerSocket
        }

        params = instance.get('params')
        gpus = None
        instance_bandwidth = None
        instance_max_vnic = None
        if params:
            if params.get('gpu') is not None:
                gpus = jsonutils.loads(params.get('gpu'))
            if params.get('bandwidth') is not None:
                instance_bandwidth = params.get('bandwidth')
            if params.get('maxVnic') is not None:
                instance_max_vnic = params.get('maxVnic')

        if gpus:
            flavor_dict.update(
                {'gpu_num': len(gpus), 'gpu_mode': gpus[0].get('mode')})
        if instance_bandwidth:
            flavor_dict.update({'instance_bandwidth': instance_bandwidth})
        if instance_max_vnic:
            flavor_dict.update({'instance_max_vnic': instance_max_vnic})
        properties = instance['vmConfig'].get('properties')
        if properties:
            if properties.get("secureVmType"):
                flavor_dict.update(
                    {'secureVmType': properties.get("secureVmType")})

        cpu_qos = utils.fc_qos_convert(instance['vmConfig']['cpu'],
                                       constant.CPU_QOS_FC_KEY,
                                       constant.CPU_QOS_FC_KEY,
                                       flavor_dict.get('vcpus'))
        flavor_dict = utils.dict_add(flavor_dict, cpu_qos)
        return flavor_dict

    def _gen_new_flavor_for_fc(self, flavor):
        """_gen_new_flavor_for_fc

        :param flavor:
        :return:
        """
        flavor_dict = {
            'vcpus': flavor['vcpus'],
            'memory_mb': flavor['memory_mb']
        }
        extra_specs = flavor.get('extra_specs', None)
        if extra_specs:
            socketNum = extra_specs.get('hw:numa_nodes', None)
            if socketNum:
                flavor_dict = utils.dict_add(
                    flavor_dict, {'socketNum': socketNum})

            gpu_num = None
            enable_gpu = extra_specs.get('pci_passthrough:enable_gpu')
            gpu_specs = extra_specs.get('pci_passthrough:gpu_specs')
            if enable_gpu and str(enable_gpu).upper() == 'TRUE':
                if gpu_specs:
                    gpu_specs = gpu_specs.split(':')
                    if gpu_specs and len(gpu_specs) == 3:
                        gpu_mode = gpu_specs[1]
                        gpu_num = gpu_specs[2]
            if gpu_num:
                flavor_dict.update(
                    {'gpu_num': int(gpu_num), 'gpu_mode': gpu_mode})
            secure_vm_type = extra_specs.get('secuirty:instance_type')
            if secure_vm_type and str(secure_vm_type).upper() == 'GVM':
                flavor_dict.update({'secureVmType': 'GVM'})
            elif secure_vm_type and str(secure_vm_type).upper() == 'SVM':
                flavor_dict.update({'secureVmType': 'SVM'})

            instance_bandwidth = None
            instance_max_vnic = None
            instance_vnic_type = extra_specs.get('instance_vnic:type')
            if instance_vnic_type and instance_vnic_type.lower() == 'enhanced':
                instance_bandwidth = extra_specs.get(
                    'instance_vnic:instance_bandwidth')
                instance_max_vnic = extra_specs.get('instance_vnic:max_count')

            if instance_bandwidth:
                flavor_dict.update(
                    {'instance_bandwidth': int(instance_bandwidth)})
            if instance_max_vnic:
                flavor_dict.update(
                    {'instance_max_vnic': int(instance_max_vnic)})

            cpu_qos = utils.fc_qos_convert(extra_specs,
                                           constant.CPU_QOS_NOVA_KEY,
                                           constant.CPU_QOS_FC_KEY,
                                           flavor_dict.get('vcpus'))
            flavor_dict = utils.dict_add(flavor_dict, cpu_qos)
        return flavor_dict

    def list_all_fc_instance(self):
        """list_all_fc_instance

        List all vm info
        :return:
        """
        fc_all_vms = FC_MGR.get_all_vms(isTemplate='false',
                                        group=constant.VM_GROUP_FLAG)
        cluster_urn_list = self._cluster_ops.get_local_cluster_urn_list()
        result = []
        for fc_vm in fc_all_vms:
            if fc_vm['clusterUrn'] in cluster_urn_list:
                result.append(fc_vm)
        LOG.debug(_("after filtered by clusters, instance number is %d"),
                  len(result))
        return result

    def get_vnc_console(self, instance, get_opt):
        """Get the vnc console information

        :param instance: the instance info
        :return: HuaweiConsoleVNC or ConsoleVNC
        """
        LOG.debug(_("start to get %s vnc console"), instance['uuid'])
        fc_vm = FC_MGR.get_vm_by_uuid(instance)
        host_ip = fc_vm.vncAcessInfo.get('hostIp', None)
        host_port = fc_vm.vncAcessInfo.get('vncPort', None)

        # raise exception if no information is provided
        if not host_port or not host_ip:
            raise exception.ConsoleNotFoundForInstance(instance_uuid=
                                                       instance['uuid'])

        if get_opt is False:
            return ctype.ConsoleVNC(host=host_ip, port=host_port)

        password = fc_vm.vncAcessInfo.get('vncPassword', None)

        return hwtype.HuaweiConsoleVNC(host_ip, host_port, password, None)

    def attach_interface(self, instance, vif, extra_specs):
        """Send message to fusion compute virtual machine

        :param instance:
        :param vif:
        :return: response : {"taskUrn": string, "taskUri": string}
        """
        checksum_enable = False
        vif_profile = vif.get('profile')
        if vif_profile:
            checksum = vif_profile.get('checksum_enable')
            if checksum:
                if str(checksum).upper() == "TRUE":
                    checksum_enable = True
        fc_vm = FC_MGR.get_vm_by_uuid(instance)
        attach_interface_uri = fc_vm.get_vm_action_uri('nics')

        pg_urn = self._network_ops.ensure_network(
            vif['network'], checksum_enable, extra_specs)
        vsp_body = {
            'name': vif['id'],
            'portId': vif['id'],
            'portGroupUrn': pg_urn,
            'mac': vif['address'],
            'virtIo': 1 if str(
                fc_vm.osOptions.get('osVersion')) in
                           constant.VIRTUAL_IO_OS_LIST else 0}
        LOG.info("the vsp information is %s", vsp_body)

        response = self.post(attach_interface_uri,
                             data=vsp_body,
                             excp=exception.InterfaceAttachFailed)
        LOG.info('send attach interface finished, return is: %s',
                 jsonutils.dumps(response))

        return response

    def detach_interface(self, instance, vif):
        """Send message to fusion compute virtual machine

        :param instance:
        :param vif:
        :return: response : {"taskUrn": string, "taskUri": string}
        if the nic does not exited, return {} else {"taskUrn": string,
        "taskUri": string}
        """
        response = {}
        fc_vm = FC_MGR.get_vm_by_uuid(instance)
        nics = fc_vm["vmConfig"]["nics"]
        LOG.info("nics in FusionCompute is %s", nics)
        nic_uri = None
        for nic in nics:
            if nic['portId'] == vif['id'] or nic['name'] == vif['id']:
                nic_uri = nic['uri']
                break

        if nic_uri:
            detach_interface_uri = (nic_uri.replace("nics", "virtualNics"))
            LOG.info("detach_interface_uri is %s", detach_interface_uri)
            response = self.delete(detach_interface_uri,
                                   excp=exception.InstanceInvalidState)
        else:
            LOG.warn(_("detach interface for vm name: %s, not exist nic."),
                     instance['name'])
        LOG.info(_('send detach interface finished, return is: %s'),
                 jsonutils.dumps(response))
        return response

    @utils.timelimited(constant.CONF.fusioncompute.fc_request_timeout_min)
    def get_info(self, instance):
        """Get vm info from instance

        :param instance:
        :return:
        """
        fc_vm = FC_MGR.get_vm_state(instance)

        # STOPPING is VM temp state, so just return prestate
        if fc_vm.status == constant.VM_STATUS.STOPPING:
            state = instance.vm_state
        else:
            state = constant.VM_POWER_STATE_MAPPING.get(fc_vm.status,
                                                        power_state.NOSTATE)

            vm_params = fc_vm.get('params', None)
            if vm_params is not None:
                notify_ret = vm_params.get('NOTIFY_NEUTRON', None)
                if notify_ret is not None and notify_ret\
                        == constant.NOTIFY_NEUTRON.FALSE:
                    LOG.error(_("get_info %s is error."), instance['uuid'])
                    state = power_state.NOSTATE

        class StateInfo(object):

            def __init__(self, state, name):
                self.state = state
                self.name = name
        return StateInfo(state=state, name=fc_vm.name)

    def get_instances_info(self):
        """Get all instances info from FusionCompute

        :return:
        """
        return FC_MGR.get_all_vms_info()

    def _check_if_vol_in_instance(self, instance, vol_urn):
        """_check_if_vol_in_instance

        :param instance: fc vm
        :param vol_urn:
        :return:
        """
        for vol in instance['vmConfig']['disks']:
            if vol_urn == vol['volumeUrn']:
                return True
        return False

    def _get_vol_urn_from_connection(self, connection_info):
        """_get_vol_urn_from_connection

        :param connection_info:
        :return:
        """
        vol_urn = connection_info.get('vol_urn')
        if vol_urn is None:
            msg = (_("invalid connection_info: %s."), connection_info)
            raise exception.Invalid(msg)
        return vol_urn

    def _volume_action(self, action, vol_urn, fc_vm, mountpoint=None,
                       is_snapshot_del=True):
        """_volume_action

        :param action: attach or detach
        :param vol_urn:
        :param fc_vm:
        :return:
        """

        if mountpoint is None:
            body = {
                'volUrn': vol_urn
            }
        else:
            body = {
                'volUrn': vol_urn,
                'sequenceNum': self.get_sequence_num(vol_urn, mountpoint)
            }
        if action == self._volume_ops.detach_volume:
            action(fc_vm, vol_config=body, is_snapshot_del=is_snapshot_del)
        else:
            action(fc_vm, vol_config=body)

    def get_sequence_num(self, vol_urn, mountpoint):

        if constant.CONF.fusioncompute.reserve_disk_symbol is None or str(
                constant.CONF.fusioncompute.reserve_disk_symbol).upper() \
                == 'TRUE':
            return constant.MOUNT_DEVICE_SEQNUM_MAP.get(mountpoint)

        vol_id = vol_urn[vol_urn.rfind(':') + 1:]
        fc_volume = self._volume_ops.query_volume(id=vol_id)
        if fc_volume:
            if fc_volume.get('pvscsiSupport') == 1 or fc_volume.get(
                    'storageType') == 'LUN':
                return constant.MOUNT_DEVICE_SEQNUM_MAP.get(mountpoint)
            else:
                return constant.MOUNT_DEVICE_SEQNUM_MAP_IDE.get(mountpoint)
        else:
            reason = _("The volume is not existed in FusionCompute.")
            raise fc_exc.InstanceAttachvolFailure(reason=reason)

    def attach_volume(self, connection_info, instance, mountpoint):
        """Attach volume for vm

        :param connection_info:
        :param instance:
        :return:
        """
        LOG.info(_("trying to attach vol for vm: %s.") % instance['uuid'])
        # 0. set qos io
        self._volume_ops.set_qos_specs_to_volume(connection_info)

        # 1. volume can only be attached when vm is running or stopped
        fc_vm = FC_MGR.get_vm_by_uuid(instance)
        if fc_vm.status not in [constant.VM_STATUS.RUNNING,
                                constant.VM_STATUS.STOPPED]:
            reason = _("vm status is not running or stopped !")
            raise fc_exc.InstanceAttachvolFailure(reason=reason)

        # 2. ignore this op when vm already has this volume
        vol_urn = self._get_vol_urn_from_connection(connection_info)
        if self._check_if_vol_in_instance(fc_vm, vol_urn) is True:
            return

        @nova_utils.synchronized(INSTANCES_ACTION_SEMAPHORE % fc_vm.uuid)
        def _attach_with_lock():
            self._volume_action(self._volume_ops.attach_volume,
                                vol_urn, fc_vm, mountpoint)

        # 3. attach this volume
        _attach_with_lock()

    def detach_volume(self, connection_info, instance, is_snapshot_del=True):
        """Detach volume for vm

        :param connection_info:
        :param instance:
        :return:
        """
        LOG.info(_("trying to detach vol for vm: %s.") % instance['uuid'])

        # 1. volume can only be detached when vm is running or stopped
        fc_vm = FC_MGR.get_vm_by_uuid(instance)
        if fc_vm.status not in [constant.VM_STATUS.RUNNING,
                                constant.VM_STATUS.STOPPED]:
            reason = _("vm status is not running or stopped !")
            raise fc_exc.InstanceDetachvolFailure(reason=reason)

        # 2. ignore this op when vm do not have this volume
        vol_urn = self._get_vol_urn_from_connection(connection_info)
        if self._check_if_vol_in_instance(fc_vm, vol_urn) is False:
            return

        # 3. detach this volume
        self._volume_action(self._volume_ops.detach_volume, vol_urn, fc_vm,
                            None, is_snapshot_del)

    def _generate_image_metadata(self, fc_vm, instance):
        """_generate_image_metadata

        :param fc_vm: fc instance
        :param instance:
        :return:
        """

        os_type = fc_vm['osOptions']['osType']
        os_version = str(fc_vm['osOptions']['osVersion'])

        metadata = {
            'disk_format': 'vhd',
            'container_format': 'bare',
            'properties': {
                'owner_id': instance['project_id'],
                constant.HUAWEI_OS_TYPE: os_type,
                constant.HUAWEI_OS_VERSION:
                    constant.HUAWEI_OS_VERSION_STR[os_type][os_version],
                constant.HUAWEI_IMAGE_TYPE: 'glance'
            }
        }

        if instance['kernel_id']:
            metadata['properties']['kernel_id'] = instance['kernel_id']
        if instance['ramdisk_id']:
            metadata['properties']['ramdisk_id'] = instance['ramdisk_id']

        return metadata

    def snapshot(self, context, instance, image_href, update_task_state):
        """Create sys vol image and upload to glance

        :param instance:
        :param image_href:
        :param update_task_state:
        :return:
        """

        _image_service, image_id = \
            glance.get_remote_image_service(context, image_href)
        metadata = {'__image_location': ''}
        image_property = {'properties': metadata}
        _image_service.update(context, image_id, image_property,
                              purge_props=False)

        LOG.info(_("update image location to null"))
        update_task_state(task_state=task_states.IMAGE_PENDING_UPLOAD)

        need_boot = False
        fc_vm = FC_MGR.get_vm_by_uuid(instance)
        if fc_vm.status == constant.VM_STATUS.RUNNING:
            LOG.info(_("stop vm before export it to glance ..."))
            need_boot = True
            self.stop_vm(instance, force=True)

        metadata = self._generate_image_metadata(fc_vm, instance)
        _image_service.update(context, image_id, metadata)

        update_task_state(task_state=task_states.IMAGE_UPLOADING,
                          expected_state=task_states.IMAGE_PENDING_UPLOAD)

        body = {
            'name': _image_service.show(context, image_id).get('name'),
            'format': 'ovf',
            'protocol': 'glance',
            'glanceConfig': {
                'endPoint': ':'.join([str(constant.CONF.fusioncompute.host),
                                      str(constant.CONF.fusioncompute.port)]),
                'serverIp': constant.CONF.fusioncompute.glance_server_ip,
                'token': context.auth_token,
                'imageID': image_id
            }
        }
        self.post(fc_vm.get_vm_action_uri('export'), data=body)

        if need_boot:
            LOG.info(_("start it after export"))
            self.start_vm(instance)

    def reconfigure_affinity_group(self, instances, affinity_group, action,
                                   node=None):
        """reconfigure_affinity_group

        :param instances:
        :param affinity_group:
        :param action:
        :param node:
        :return:
        """

        LOG.info(_("begin reconfigure affinity group ..."))

        # 1. all vms passed in should in the same cluster
        if node is None and len(instances) > 0:
            node = instances[0].get('node')

        if node is None:
            msg = _("Can not get any node info !")
            raise fc_exc.AffinityGroupException(reason=msg)

        for instance in instances:
            if node != instance.get('node'):
                msg = _("VMs cluster must be same !")
                raise fc_exc.AffinityGroupException(reason=msg)

        # 2. get fc cluster object
        cluster = self._cluster_ops.get_cluster_detail_by_nodename(node)
        if cluster is None:
            raise fc_exc.ClusterNotFound(cluster_name=node)

        # 3. do reconfigure
        rule_name = str(affinity_group.id)
        rule_type = constant.DRS_RULES_TYPE_MAP.get(affinity_group.type) or \
            constant.DRS_RULES_TYPE_MAP['affinity']

        if action == 'remove':
            self._cluster_ops.delete_drs_rules(cluster, rule_name, rule_type)
            LOG.info(_("delete affinity group success and return"))
            return

        if action == 'add':
            self._cluster_ops.create_drs_rules(cluster, rule_name, rule_type)
            cluster = self._cluster_ops.get_cluster_detail_by_nodename(node)
            LOG.info(_("create affinity group success"))

        vms = []
        for instance in instances:
            instance['uuid'] = instance['name']
            fc_vm = FC_MGR.get_vm_by_uuid(instance)
            vm_info = {
                'urn': fc_vm['urn'],
                'name': fc_vm['name']
            }
            vms.append(vm_info)

        try:
            self._cluster_ops.\
                modify_drs_rules(cluster, rule_name, rule_type, vms)
        except Exception as exc:
            LOG.error(_("modify drs rules failed !"))
            if action == 'add':
                self._cluster_ops.\
                    delete_drs_rules(cluster, rule_name, rule_type)
            raise exc

        LOG.info(_("reconfigure affinity group success"))
