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
import inspect

from nova import exception as nova_exc
from oslo_serialization import jsonutils
from nova.i18n import _
from nova import context as nova_context
import time
import exception
from nova.virt.fusioncomputeapi import exception as fc_exc
from nova import objects
from nova.virt import driver as compute_driver
from nova.virt.fusioncomputeapi.fcclient import FCBaseClient
from nova.virt.fusioncomputeapi import computeops
from nova.virt.fusioncomputeapi import cluster as fc_cluster
from nova.virt.fusioncomputeapi import networkops
from nova.virt.fusioncomputeapi import taskops
from nova.virt.fusioncomputeapi import volumeops
from nova.virt.fusioncomputeapi import utils
from nova.virt.fusioncomputeapi import constant
from nova.virt.fusioncomputeapi.fcinstance import FC_INSTANCE_MANAGER as FC_MGR
from nova.virt.fusioncomputeapi.utils import LOG
#from FSSecurity import crypt


class FusionComputeDriver(compute_driver.ComputeDriver):
    """FusionComputeDriver: for OpenStack Manager"""

    def __init__(self, virtapi):
        LOG.info(_('begin to init FusionComputeDriver ...'))
        super(FusionComputeDriver, self).__init__(virtapi)

        self._client = FCBaseClient(
            constant.CONF.fusioncompute.fc_ip,
            constant.CONF.fusioncompute.fc_user,
            constant.CONF.fusioncompute.fc_pwd,
            constant.FC_DRIVER_JOINT_CFG['user_type'],
            ssl=True,
            port=constant.FC_DRIVER_JOINT_CFG['fc_port'],
            api_version=constant.FC_DRIVER_JOINT_CFG['api_version'],
            request_time_out=constant.FC_DRIVER_JOINT_CFG['request_time_out'])
        self._client.set_default_site()

        # task ops is need by other ops, init it first
        self.task_ops = taskops.TaskOperation(self._client)
        FC_MGR.set_client(self._client)

        self.network_ops = networkops.NetworkOps(self._client, self.task_ops)
        self.volume_ops = volumeops.VolumeOps(self._client, self.task_ops)
        self.cluster_ops = fc_cluster.ClusterOps(self._client, self.task_ops)
        self.compute_ops = computeops.ComputeOps(self._client, self.task_ops,
                                                 self.network_ops,
                                                 self.volume_ops,
                                                 self.cluster_ops)

    def _list_all_clusters(self):
        LOG.debug(_("_list_all_clusters"))
        return self.cluster_ops.list_all_clusters()

    def is_fc_up(self):
        LOG.debug(_("is_fc_up"))
        try:
            clusters = self._list_all_clusters()
        except Exception as ex:
            LOG.error(_("is_fc_up %s") % ex)
            return False
        if clusters is None:
            LOG.error(_("is_fc_up clusters is None"))
            return False
        if len(clusters) < 1:
            LOG.error(_("len clusters is zero"))
            return False

        return True

    def init_host(self, host):
        """FC driver init goes here"""
        pass

    def get_info(self, instance):
        """Get the current status of an instance by uuid

        :param instance:
        :return:
        """
        return self.compute_ops.get_info(instance)

    def get_instance_extra_specs(self, instance):
        """

        get instance extra info
        :param instance:
        :return:
        """
        # ignore pylint:disable=E1101
        inst_type = objects.Flavor.get_by_id(
            nova_context.get_admin_context(read_deleted='yes'),
            instance['instance_type_id'])
        return inst_type.get('extra_specs', {})

    def get_resource_group_list(self):
        """

        get instance group list
        :param instance:
        :return:
        """

        node_list = self.get_available_nodes()
        resource_groups = []
        if node_list:
            for node in node_list:
                cluster_urn = self.cluster_ops.get_cluster_urn_by_nodename(
                    node)
                resource_groups_per_cluster = self.cluster_ops.get_resource_group_list(
                    cluster_urn)
                resource_groups.extend(resource_groups_per_cluster)
        return resource_groups

    def delete_resource_group(self, resource_group_urn):
        """

        delete instance group list
        :param : resource_group_urn
        :return:
        """
        self.cluster_ops.delete_resource_group(resource_group_urn)

    @utils.timelimited(constant.CONF.fusioncompute.fc_request_timeout_max)
    def _get_instances_info(self):
        """

        Get all instances info from FusionCompute
        :return:
        """
        return self.compute_ops.get_instances_info()

    def get_instances_info(self):
        """

        Get all instances info from FusionCompute
        :return:
        """
        LOG.debug(_("get_instances_info"))
        try:
            instances = self._get_instances_info()
        except Exception as ex:
            LOG.error(_("get_instances_info: %s") % ex)
            return {}
        if instances is None:
            return {}
        return instances

    def get_instance_disk_info(self, instance_name,
                               block_device_info=None):
        """Retrieve information about actual disk sizes of an instance.

        :param instance_name:
            name of a nova instance as returned by list_instances()
        :param block_device_info:
            Optional; Can be used to filter out devices which are
            actually volumes.
        :return:
            json strings with below format::

                "[{'path':'disk',
                   'type':'raw',
                   'virt_disk_size':'10737418240',
                   'backing_file':'backing_file',
                   'disk_size':'83886080'
                   'over_committed_disk_size':'10737418240'},
                   ...]"
        """
        return [{}]

    def spawn(self, context, instance, image_meta, injected_files,
              admin_password, network_info=None, block_device_info=None):
        """ Create vm.

        :param context:
        :param instance:
        :param image_meta:
        :param injected_files:
        :param admin_password:
        :param network_info:
        :param block_device_info:
        :return:
        """
        #@utils.func_log_circle(instance)
        def _create_vm():
            """

            inner create vm
            :return:
            """
            extra_specs = self.get_instance_extra_specs(instance)
            LOG.debug(_("extra_specs is %s."), jsonutils.dumps(extra_specs))

            vm_password = admin_password if constant.CONF.fusioncompute.use_admin_pass\
                else None

            # create vm on FC
            self.compute_ops.create_vm(context, instance, network_info,
                                       block_device_info,
                                       image_meta, injected_files,
                                       vm_password, extra_specs)
        _create_vm()

    def power_off(
            self,
            instance,
            timeout=0,
            retry_interval=0,
            forceStop=False):
        """Power off the specified instance.

        :param instance: nova.objects.instance.Instance
        """
        @utils.func_log_circle(instance, nova_exc.InstanceFaultRollback)
        def _stop_vm():
            """

            inner stop vm
            :return:
            """
            self.compute_ops.stop_vm(instance, forceStop)

        _stop_vm()

    def power_on(self, context, instance, network_info,
                 block_device_info=None):
        """Power on the specified instance.

        :param instance: nova.objects.instance.Instance
        """
        @utils.func_log_circle(instance)
        def _start_vm():
            """

            inner start vm
            :return:
            """
            self.compute_ops.start_vm(instance, block_device_info)

        _start_vm()

    def reboot(self, context, instance, network_info, reboot_type,
               block_device_info=None, bad_volumes_callback=None):
        @utils.func_log_circle(instance)
        def _reboot_vm_fc():
            """

            inner reboot vm
            :return:
            """
            try:
                self.compute_ops.reboot_vm(
                    instance, reboot_type, block_device_info)
            except Exception as ex:
                LOG.error(_("reboot_vm exception: %s") % ex)

        _reboot_vm_fc()

    def cleanup(self, context, instance, network_info, block_device_info=None,
                destroy_disks=True, migrate_data=None, destroy_vifs=True):
        """Cleanup the instance resources ."""
        pass

    def destroy(self, context, instance, network_info, block_device_info=None,
                destroy_disks=True, migrate_data=None):
        """FC itself will clean up network and disks"""
        @utils.func_log_circle(instance)
        def _delete_vm():
            """
            inner delete vm
            :return:
            """
            self.compute_ops.delete_vm(context, instance,
                                       block_device_info=block_device_info,
                                       destroy_disks=destroy_disks)
        _delete_vm()

    def pause(self, instance):
        """Pause the specified instance.

        :param instance: nova.objects.instance.Instance
        """
        @utils.func_log_circle(instance)
        def _pause_vm():
            """

            inner pause vm
            :return:
            """
            self.compute_ops.pause_vm(instance)
        _pause_vm()

    def unpause(self, instance):
        """Unpause paused instance.

        :param instance: nova.objects.instance.Instance
        """
        @utils.func_log_circle(instance)
        def _unpause_vm():
            """

            inner unpause vm
            :return:
            """
            self.compute_ops.unpause_vm(instance)
        _unpause_vm()

    def suspend(self, context, instance):
        """Suspend instance.

        :param instance: nova.objects.instance.Instance
        """
        @utils.func_log_circle(instance, nova_exc.InstanceFaultRollback)
        def _suspend_vm():
            """

            inner unpause vm
            :return:
            """
            self.compute_ops.suspend_vm(instance)
        _suspend_vm()

    def resume(self, context, instance, network_info, block_device_info=None):
        """resume the specified instance.

        :param context: the context for the resume
        :param instance: nova.objects.instance.Instance being resumed
        :param network_info:
           :py:meth:`~nova.network.manager.NetworkManager.get_instance_nw_info`
        :param block_device_info: instance volume block device info
        """
        @utils.func_log_circle(instance)
        def _resume_vm():
            """

            inner resume vm, same action as start_vm in FC
            :return:
            """
            self.compute_ops.start_vm(instance, block_device_info)

        _resume_vm()

    def change_instance_metadata(self, context, instance, diff):
        """

        :param context:
        :param instance:
        :param diff:
        :return:
        """
        @utils.func_log_circle(instance)
        def _change_instance_metadata():
            """

            :return:
            """
            self.compute_ops.change_instance_metadata(instance)
        _change_instance_metadata()

    def change_instance_info(self, context, instance):
        """

        :param context:
        :param instance:
        :return:
        """
        @utils.func_log_circle(instance)
        def _change_instance_info():
            """

            :return:
            """
            self.compute_ops.change_instance_info(instance)
        _change_instance_info()

    def resume_state_on_host_boot(self, context, instance, network_info,
                                  block_device_info=None):
        """resume guest state when a host is booted.

        FC can do HA automatically, so here we only rewrite this interface
        to avoid NotImplementedError() in nova-compute.log

        :param instance: nova.objects.instance.Instance
        """
        pass

    def confirm_migration(self, migration, instance, network_info):
        """Confirms a resize, destroying the source VM.

        :param instance: nova.objects.instance.Instance
        """
        @utils.func_log_circle(instance, nova_exc.InstanceFaultRollback)
        def _confirm_migration():
            """

            inner confirm migration
            :return:
            """
            self.compute_ops.confirm_migration(instance)
        _confirm_migration()

    def pre_live_migration(self, ctxt, instance, block_device_info,
                           network_info, disk_info, migrate_data=None):
        """Prepare an instance for live migration"""

        # do nothing on FC
        pass

    def check_can_live_migrate_destination(self, context, instance,
                                           src_compute_info, dst_compute_info,
                                           block_migration=False,
                                           disk_over_commit=False):
        """Check if it is possible to execute live migration.

        This runs checks on the destination host, and then calls
        back to the source host to check the results.

        :param context: security context
        :param instance: nova.db.sqlalchemy.models.Instance
        :param src_compute_info: Info about the sending machine
        :param dst_compute_info: Info about the receiving machine
        :param block_migration: if true, prepare for block migration
        :param disk_over_commit: if true, allow disk over commit
        :returns: a dict containing migration info (hypervisor-dependent)
        """
        return {}

    def check_can_live_migrate_destination_cleanup(self, context,
                                                   dest_check_data):
        """Do required cleanup on dest host after check_can_live_migrate calls

        :param context: security context
        :param dest_check_data: result of check_can_live_migrate_destination
        """
        pass

    def check_can_live_migrate_source(self, context, instance,
                                      dest_check_data, block_device_info=None):
        """Check if it is possible to execute live migration.

        This checks if the live migration can succeed, based on the
        results from check_can_live_migrate_destination.

        :param context: security context
        :param instance: nova.db.sqlalchemy.models.Instance
        :param dest_check_data: result of check_can_live_migrate_destination
        :param block_device_info: result of _get_instance_block_device_info
        :returns: a dict containing migration info (hypervisor-dependent)
        """
        return {}

    def ensure_filtering_rules_for_instance(self, instance, network_info):
        """Setting up filtering rules and waiting for its completion.

        To migrate an instance, filtering rules to hypervisors
        and firewalls are inevitable on destination host.
        ( Waiting only for filtering rules to hypervisor,
        since filtering rules to firewall rules can be set faster).

        Concretely, the below method must be called.
        - setup_basic_filtering (for nova-basic, etc.)
        - prepare_instance_filter(for nova-instance-instance-xxx, etc.)

        to_xml may have to be called since it defines PROJNET, PROJMASK.
        but libvirt migrates those value through migrateToURI(),
        so , no need to be called.

        Don't use thread for this method since migration should
        not be started when setting-up filtering rules operations
        are not completed.

        :param instance: nova.objects.instance.Instance object

        """
        pass

    def unfilter_instance(self, instance, network_info):
        """Stop filtering instance."""
        pass

    # ignore pylint:disable=W0613
    def live_migration(self, context, instance_ref, dest,
                       post_method, recover_method, block_migration=False,
                       migrate_data=None):
        """Live migration of an instance to another host."""
        @utils.func_log_circle(instance_ref)
        def _live_migration():
            """

            inner live migrate vm
            :return:
            """
            self.compute_ops.live_migration(
                context,
                instance_ref,
                dest,
                post_method,
                recover_method,
                block_migration,
                migrate_data)
        _live_migration()

    def post_live_migration(self, ctxt, instance_ref, block_device_info,
                            migrate_data=None):
        """Post operation of live migration at source host."""

        # do nothing on FC
        pass

    def post_live_migration_at_destination(self, context, instance,
                                           network_info,
                                           block_migration=False,
                                           block_device_info=None):
        """Post operation of live migration at destination host."""

        def _post_live_migration_at_destination():
            self.compute_ops.post_live_migration_at_destination(instance)
        _post_live_migration_at_destination()

    def post_live_migration_at_source(self, context, instance, network_info):
        """Unplug VIFs from networks at source.

        :param context: security context
        :param instance: instance object reference
        :param network_info: instance network information
        """
        # do nothing on FC
        pass

    def rollback_live_migration_at_destination(self, ctxt, instance_ref,
                                               network_info,
                                               block_device_info,
                                               destroy_disks=True,
                                               migrate_data=None):
        """Clean up destination node after a failed live migration."""

        # do nothing on FC
        pass

    def get_volume_connector(self, instance):
        return {'ip': constant.CONF.my_ip,
                'host': constant.CONF.host}

    def instance_exists(self, instance):
        try:
            FC_MGR.get_vm_by_uuid(instance)
            return True
        except nova_exc.InstanceNotFound:
            return False

    def get_available_resource(self, nodename):
        """Retrieve resource info.

        This method is called when nova-compute launches, and
        as part of a periodic task.

        :returns: dictionary describing resources
        """
        return self.cluster_ops.get_available_resource(nodename)

    def get_host_stats(self, refresh=False):
        """Return currently known host stats."""

        stats_list = []
        nodes = self.get_available_nodes_without_exception(refresh=refresh)
        for node in nodes:
            stats_list.append(self.get_available_resource(node))
        return stats_list

    def node_is_available(self, nodename):
        """Return whether this compute service manages a particular node."""
        if nodename in self.get_available_nodes_without_exception():
            return True
        # Refresh and check again.
        return nodename in self.get_available_nodes_without_exception(
            refresh=True)

    def get_host_ip_addr(self):
        """Retrieves the IP address of the dom0

        """
        # Avoid NotImplementedError
        pass

    @utils.timelimited(constant.CONF.fusioncompute.fc_request_timeout_min)
    def _get_available_nodes(self, refresh=True):
        """Returns nodenames of all nodes managed by the compute service."""

        LOG.debug(_("_get_available_nodes"))
        # default is refresh to ensure it is latest
        if refresh:
            try:
                self.cluster_ops.update_resources()
            except Exception as ex:
                LOG.error(_("get clusters from fc exception"))
                LOG.exception(ex)
                raise ex

        node_list = self.cluster_ops.resources
        LOG.debug(_("_get_available_nodes: %s") % node_list)
        return node_list

    def get_available_nodes(self, refresh=True):
        """Returns nodenames of all nodes managed by the compute service."""

        LOG.debug(_("get_available_nodes"))

        node_list = self._get_available_nodes(refresh)

        # node_list is None only when exception is throwed.
        if node_list is None:
            raise nova_exc.HypervisorUnavailable(host='fc-nova-compute')
        else:
            return node_list

    def get_available_nodes_without_exception(self, refresh=True):
        """Returns nodenames of all nodes managed by the compute service."""

        LOG.debug(_("get_available_nodes"))
        try:
            node_list = self._get_available_nodes(refresh)
        except Exception as ex:
            LOG.error(_("get_available_nodes: %s") % ex)
            return []
        if node_list is None:
            return []
        else:
            return node_list

    def get_hypervisor_version(self):
        """Get hypervisor version."""
        return self.cluster_ops.get_hypervisor_version()

    def get_hypervisor_type(self):
        """Returns the type of the hypervisor."""
        return self.cluster_ops.get_hypervisor_type()

    def get_instance_capabilities(self):
        """get_instance_capabilities"""
        return self.cluster_ops.get_instance_capabilities()

    @utils.timelimited(constant.CONF.fusioncompute.fc_request_timeout_min)
    def _list_instances(self):
        LOG.debug(_("_list_instances"))
        instances = self.compute_ops.list_all_fc_instance()
        return instances

    def list_instances(self):
        LOG.debug(_("list_instances"))
        try:
            instances = self._list_instances()
        except Exception as ex:
            LOG.debug(_("The available nodes are: %s") % ex)
            return []
        if instances is None:
            LOG.error(_("instances is None"))
            return []
        else:
            return [vm['name'] for vm in instances]

    @utils.timelimited(constant.CONF.fusioncompute.fc_request_timeout_min)
    def _list_instance_uuids(self):
        """_list_instance_uuids"""
        fc_instances = self.compute_ops.list_all_fc_instance()
        return fc_instances

    def list_instance_uuids(self):
        """list_instance_uuids"""
        try:
            fc_instances = self._list_instance_uuids()
        except Exception as ex:
            LOG.error(_("list_instance_uuids: %s") % ex)
            return []
        if fc_instances is None:
            LOG.error(_("fc_instances is None"))
            return []
        return [vm['uuid'] for vm in fc_instances]

    def get_vnc_console(self, context, instance):
        """Get connection info for a vnc console.

        :param instance: nova.objects.instance.Instance
        """
        # return password only in called by manager.get_vnc_console
        # if called by manager.validate_console_port, return without password
        get_opt = True
        stack_list = inspect.stack()
        if str(stack_list[1][3]) != "get_vnc_console":
            get_opt = False

        return self.compute_ops.get_vnc_console(instance, get_opt)

    def attach_interface(self, instance, image_meta, vif):
        """

        attach interface into fusion compute virtual machine, now
        do not consider inic network interface

        :param instance:
        :param image_meta:
        :param vif:
        :return:
        """

        @utils.func_log_circle(instance)
        @utils.timelimited(constant.CONF.fusioncompute.attach_int_timeout)
        def attach_intf_inner():
            """

            inner attach interface
            """
            extra_specs = self.get_instance_extra_specs(instance)
            return self.compute_ops.attach_interface(
                instance, vif, extra_specs)
        try:
            return attach_intf_inner()
        except exception.TimeoutError as ex:
            LOG.warn("TimeoutError %s", ex)
            return
        except Exception as ex:
            LOG.error("Exception %s", ex)
            raise ex

    def detach_interface(self, instance, vif):
        """

        detach interface from fusion compute virtual machine, if the nic has
        not exited, don't raise exception

        :param instance:
        :param vif:
        :return:
        """

        @utils.func_log_circle(instance)
        def detach_intf_inner():
            """

            inner detach interface
            :return:
            """
            return self.compute_ops.detach_interface(instance, vif)
        return detach_intf_inner()

    def migrate_disk_and_power_off(self, context, instance, dest, flavor,
                                   network_info, block_device_info=None,
                                   timeout=0, retry_interval=0):
        """Transfers the disk of a running instance in multiple phases, turning
        off the instance before the end.

        :param instance: nova.objects.instance.Instance
        """
        @utils.func_log_circle(instance, nova_exc.InstanceFaultRollback)
        def _migrate_disk_and_power_off():
            """

            inner modify vm
            :return:
            """
            self.compute_ops.migrate_disk_and_power_off(
                instance, dest, flavor, block_device_info)
        _migrate_disk_and_power_off()

    def finish_migration(self, context, migration, instance, disk_info,
                         network_info, image_meta, resize_instance,
                         block_device_info=None, power_on=True):
        """Completes a resize.

        :param context: the context for the migration/resize
        :param migration: the migrate/resize information
        :param instance: nova.objects.instance.Instance being migrated/resized
        :param disk_info: the newly transferred disk information
        :param network_info:
           :py:meth:`~nova.network.manager.NetworkManager.get_instance_nw_info`
        :param image_meta: image object returned by nova.image.glance that
                           defines the image from which this instance
                           was created
        :param resize_instance: True if the instance is being resized,
                                False otherwise
        :param block_device_info: instance volume block device info
        :param power_on: True if the instance should be powered on, False
                         otherwise
        """
        @utils.func_log_circle(instance)
        def _finish_migration():
            """

            inner finish migrate vm
            :return:
            """
            self.compute_ops.finish_migration(
                instance, power_on, block_device_info)
        _finish_migration()

    def finish_revert_migration(self, context, instance, network_info,
                                block_device_info=None, power_on=True):
        """Finish reverting a resize.

        :param context: the context for the finish_revert_migration
        :param instance: nova.objects.instance.Instance being migrated/resized
        :param network_info:
           :py:meth:`~nova.network.manager.NetworkManager.get_instance_nw_info`
        :param block_device_info: instance volume block device info
        :param power_on: True if the instance should be powered on, False
                         otherwise
        """

        @utils.func_log_circle(instance)
        def _finish_revert_migration():
            """

            inner finish revert migration
            :return:
            """
            self.compute_ops.finish_revert_migration(
                instance, power_on, block_device_info)
        _finish_revert_migration()

    def attach_volume(self, context, connection_info, instance, mountpoint,
                      disk_bus=None, device_type=None, encryption=None):
        """Attach the disk to the instance at mountpoint using info."""
        @utils.func_log_circle(instance)
        def _attach_volume():
            """

            inner attach volume
            :return:
            """
            retry_num = 8
            for count in range(retry_num):
                try:
                    LOG.info(_('Attach volume count is %s '), count + 1)
                    self.compute_ops.attach_volume(connection_info,
                                                   instance,
                                                   mountpoint)
                    LOG.info(_('Attach volume success.'))
                    return
                except Exception as ex:
                    LOG.error(_('Attach volume fail %s'), repr(ex))
                    if count >= retry_num - 1:
                        raise ex
                    time.sleep(10 + count * 10)

        _attach_volume()

    def detach_volume(self, connection_info, instance, mountpoint,
                      encryption=None):
        """Detach the disk attached to the instance."""
        @utils.func_log_circle(instance)
        def _detach_volume():
            """

            inner detach volume
            :return:
            """
            retry_num = 8
            for count in range(retry_num):
                try:
                    LOG.info(_('Detach volume count is %s '), count + 1)
                    self.compute_ops.detach_volume(connection_info, instance)
                    LOG.info(_('Detach volume success.'))
                    return
                except Exception as ex:
                    LOG.error(_('Detach volume fail %s'), repr(ex))
                    if count >= retry_num - 1:
                        raise ex
                    time.sleep(10 + count * 10)

        _detach_volume()

    def snapshot(self, context, instance, image_id, update_task_state):
        """Snapshots the specified instance.

        :param context: security context
        :param instance: Instance object as returned by DB layer.
        :param image_id: Reference to a pre-created image that will
                         hold the snapshot.
        """
        @utils.func_log_circle(instance)
        def _snapshot():
            """

            create vm snapshot
            :return:
            """
            self.compute_ops.snapshot(context, instance, image_id,
                                      update_task_state)

        _snapshot()

    def report_instances_state(self, host):
        """

        Report instances state on compute starting.
        """
        pass

    def report_host_state(self, host):
        """

        Report host state on compute starting.
        """
        pass

    def get_pci_slots_from_xml(self, instance):
        """

        :param instance:
        :return:
        """
        return []

    def reconfigure_affinity_group(self, instances, affinity_group, action,
                                   node=None):
        """

        Add or Remove vms from affinity group
        :param instances:
        :param affinity_group:
        :param action:
        :param node:
        :return:
        """

        @utils.func_log_circle()
        def _reconfigure_affinity_group():
            """

            :return:
            """
            self.compute_ops.reconfigure_affinity_group(instances,
                                                        affinity_group,
                                                        action,
                                                        node)

        _reconfigure_affinity_group()

    def clean_fc_network_pg(self):
        """

        :return:
        """
        @utils.func_log_circle()
        def _clean_fc_network_pg():
            self.network_ops.audit_pg()

        _clean_fc_network_pg()
