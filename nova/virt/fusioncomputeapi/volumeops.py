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
from nova import utils as nova_utils
from nova.virt.fusioncomputeapi import constant
from nova.virt.fusioncomputeapi import exception as fc_exc
from nova.virt.fusioncomputeapi import ops_task_base
from nova.virt.fusioncomputeapi import utils
from nova.virt.fusioncomputeapi.utils import LOG
from nova.volume import cinder


class VolumeOps(ops_task_base.OpsTaskBase):
    """volume operation class

    """

    def __init__(self, fc_client, task_ops):
        super(VolumeOps, self).__init__(fc_client, task_ops)
        self._volume_api = cinder.API()

    def get_block_device_meta_data(self, context, block_device_info):
        """get volume meta data info from input info

        :param context:
        :param block_device_info:
        :return:
        """
        LOG.debug('volume info is: %s', block_device_info)
        if len(block_device_info['block_device_mapping']) > 0:
            volume_info = block_device_info['block_device_mapping'][0]
            volume_id = volume_info['connection_info']['serial']
            return self._get_volume_meta_data(context, volume_id)
        return None

    def ensure_volume(self, volume_info):
        """Ensure volume resource on FC

        :param volume_info:
        :return:
        """
        LOG.debug('volume info is: %s', volume_info)

        return [
            {
                'urn': bdm['connection_info']['vol_urn'],
                'mount_device': bdm['mount_device']
            }
            for bdm in volume_info['block_device_mapping']
        ]

    def expand_volume(self, fc_vm, vol_config):
        """Expand sys volume

        :param fc_vm: FC instance
        :param vol_config:
        :return:
        """
        vm_expandvol_uri = fc_vm.get_vm_action_uri('expandvol')
        return self.post(vm_expandvol_uri, data=vol_config,
                         excp=fc_exc.InstanceExpandvolFailure)

    def attach_volume(self, fc_vm, vol_config):
        """Attach volume for vm

        :param fc_vm: FC instance
        :param vol_config:
        :return:
        """
        vm_attachvol_uri = fc_vm.get_vm_action_uri('attachvol')
        self.post(vm_attachvol_uri, data=vol_config,
                  excp=fc_exc.InstanceAttachvolFailure)

    def detach_volume(self, fc_vm, vol_config, is_snapshot_del=True):
        """Detach volume for vm

        :param fc_vm: FC instance
        :param vol_config:
        :return:
        """

        if constant.CONF.fusioncompute.enable_snapshot_auto_del \
                and is_snapshot_del:
            snapshot_lock = "%s_snapshot" % fc_vm.uuid
            self.pre_detach_volume(snapshot_lock, fc_vm.uri,
                                   vol_config.get('volUrn'))

        vm_detachvol_uri = fc_vm.get_vm_action_uri('detachvol')
        self.post(vm_detachvol_uri, data=vol_config,
                  excp=fc_exc.InstanceDetachvolFailure)

    def create_local_disk_batch(self, **kwargs):

        uri = self.site.volume_uri + '/createinbatch'

        safe_format = kwargs.get('local_disk_safe_format')
        if safe_format and safe_format.lower == 'true':
            safe_format = True
        else:
            safe_format = False

        body = {
            'clusterUrn': kwargs.get('cluster_urn'),
            'numberOfVolumes': kwargs.get('local_disk_count'),
            'volumeSize': kwargs.get('local_disk_size'),
            'type': kwargs.get('local_disk_type'),
            'safeFormat': safe_format,
            'volumeUrns': kwargs.get('volume_urns'),
            'vmUrn': kwargs.get('fc_vm_urn'),
            'datastoreUsageMode': 0}

        response = self.post(uri, body)

        return response.get('urn')

    def delete_volume(self, vol_uri):
        """Delete volume

        :param vol_uri:
        :return:
        """
        self.delete(vol_uri, excp=fc_exc.VolumeDeleteFailure)

    def create_image_from_volume(self, vol_uri, vol, image_id):
        """create_image_from_volume

        :param vol_uri: volume action uri
        :param vol:
        :param image_id:
        :return:
        """
        body = {
            'volumePara': {
                'quantityGB': vol.get('quantityGB'),
                'urn': vol.get('volumeUrn')
            },
            'imagePara': {
                'id': image_id,
                'url': constant.CONF.fusioncompute.fc_image_path
            }
        }

        image_create_uri = vol_uri + '/volumetoimage'
        self.post(image_create_uri, data=body, excp=fc_exc.ImageCreateFailure)

    def _get_volume_meta_data(self, context, volume_id):
        """from cinder get volume metadata

        :param volume_id:
        :return:
        """
        LOG.debug(_('get_volume_meta_data enter, volume_id:%s.'), volume_id)
        return self._volume_api.get(context, volume_id)

    def set_qos_specs_to_volume(self, info):
        """set_qos_specs_to_volume

        :param info
        :return:
        """

        def _set_qos_specs_to_volume(self, connection_info):
            """_set_qos_specs_to_volume

            :param connection_info
            :return:
            """
            qos_para = {'maxReadBytes': 0,
                        'maxWriteBytes': 0,
                        'maxReadRequest': 0,
                        'maxWriteRequest': 0}
            key_cvt_map = {'read_bytes_sec': 'maxReadBytes',
                           'write_bytes_sec': 'maxWriteBytes',
                           'read_iops_sec': 'maxReadRequest',
                           'write_iops_sec': 'maxWriteRequest'}
            tune_opts = ['read_bytes_sec', 'write_bytes_sec',
                         'read_iops_sec', 'write_iops_sec']
            tune_cvt_opts = ['read_bytes_sec', 'write_bytes_sec']
            # Extract rate_limit control parameters
            if connection_info is None or 'data' not in connection_info:
                return

            specs = connection_info['data']['qos_specs']
            vol_urn = connection_info.get('vol_urn')

            if vol_urn is None:
                return

            # because the volume can be detached and attach to another instance
            # qos maybe disassociated from volume type
            # between the up two operations
            # so if specs is none,set default value to FC.
            if specs is not None:
                if isinstance(specs, dict):
                    for key, value in specs.iteritems():
                        if key in tune_opts:
                            # convert byte to KB for FC,0 is no limited,
                            # the value is at least 1
                            output_value = value

                            if key in tune_cvt_opts:
                                addition = 0
                                if output_value.isdigit():
                                    if long(value) % 1024 != 0:
                                        addition = 1
                                    output_value = long(value) / 1024 \
                                        + addition

                            qos_para[key_cvt_map[key]] = output_value
                else:
                    LOG.debug(_('Unknown content in connection_info '
                                'qos_specs: %s'), specs)
                    return

            qos_specs_uri = utils.generate_uri_from_urn(vol_urn) \
                + constant.VOL_URI_MAP['modio']

            # Send Qos IO Specs to VRM with put method
            self.put(qos_specs_uri, data=qos_para,
                     excp=fc_exc.SetQosIoFailure, fixedInterval=1)

        if isinstance(info, dict):
            # input para is block_device_info
            if 'block_device_mapping' in info:
                block_device_mapping = info.get('block_device_mapping', [])
                for vol in block_device_mapping:
                    connection_info = vol['connection_info']
                    _set_qos_specs_to_volume(self, connection_info)
            # input para is connection_info
            else:
                _set_qos_specs_to_volume(self, info)

    def query_vm_snapshot(self, instance_url):
        """query vm all snapshot and record its in list

        :param instance_url:
        :return:
        """
        def _route_all_snapshots(snapshot, snapshot_list):
            if len(snapshot_list) > 32 or \
                    isinstance(snapshot, dict) is False:
                return

            child_snapshots = snapshot.get('childSnapshots')
            if isinstance(snapshots, list) is False:
                return

            for child_snap in child_snapshots:
                _route_all_snapshots(child_snap, snapshot_list)

            node = {}
            node['name'] = snapshot.get('name')
            node['uri'] = snapshot.get('uri')
            node['status'] = snapshot.get('status')
            node['type'] = snapshot.get('type')
            snapshot_list.append(node)
            return

        def _query_snapshot_volumes(snapshot_url):
            """query all volumes in snapshot and record it in list

            """
            try:
                rsp = self.get(snapshot_url)
            except Exception as e:
                if e.message.find('10300109') > 0:
                    rsp = {}
                else:
                    msg = _('Query %s snapshot error') % snapshot_url
                    raise fc_exc.InvalidSnapshotInfo(msg)

            volsnapshots = rsp.get('volsnapshots')
            if isinstance(volsnapshots, list) is False:
                LOG.info("snapshot not include any volume, %s" % rsp)
                return []
            return map(lambda x: x.get('volumeUrn'), volsnapshots)

        snapshot_url = '%s/snapshots' % instance_url
        try:
            rsp = self.get(snapshot_url)
        except Exception as e:
            if e.message.find('10300109') > 0:
                rsp = {}
            else:
                msg = _('query %s snapshot error %s') % (snapshot_url, e)
                raise fc_exc.InvalidSnapshotInfo(msg)

        rootSnaps = rsp.get('rootSnapshots')
        if isinstance(rootSnaps, list) is False:
            return None

        snapshots = []
        for snap in rootSnaps:
            _route_all_snapshots(snap, snapshots)

        for snap in snapshots:
            snapshot_volumes = _query_snapshot_volumes(snap.get('uri'))
            snap.update({'volumeUriList': snapshot_volumes})
        return snapshots

    def need_del_backup_snapshots(self, snapshot_info_list, volume_urn):
        """need_del_backup_snapshots

        :param snapshot_info_list:
        :param volume_urn:
        :return:
        """

        def _is_vol_in_snap(snapshot_info, volume_urn):
            snapshot_volume_list = snapshot_info.get('volumeUriList')
            if isinstance(snapshot_volume_list, list) is not True:
                return False
            return volume_urn in snapshot_volume_list

        snapshots_with_volume = filter(
            lambda x: _is_vol_in_snap(
                x, volume_urn), snapshot_info_list)
        if snapshots_with_volume is None or len(snapshots_with_volume) == 0:
            LOG.info(
                "can't find volume %s in snapshot %s" %
                (volume_urn, snapshot_info_list))
            return []

        for snapshot in snapshots_with_volume:
            type = snapshot.get('type')
            status = snapshot.get('status')
            if (type != 'backup' and type != 'CBTbackup') or status != 'ready':
                msg = _('snapshot is % s and status is % s, do not del any
                        snapshot') % (type, status)
                LOG.info(msg)
                raise fc_exc.InvalidSnapshotInfo(msg)
        return snapshots_with_volume

    def pre_detach_volume(self, snapshot_lock, instance_url, volume_url):
        """pre_detach_volume

        :param instance_url:
        :param volume_url:
        :return:
        """
        def _def_vm_snapshot(snapshot_url):
            try:
                self.delete(snapshot_url)
            except Exception as e:
                if e.message.find('10300109') > 0:
                    LOG.warn("snapshot %s has been deleted" % snapshot_url)
                    pass
                else:
                    msg = _('del %s snapshot error, %s') % (snapshot_url,
                                                            e.message)
                    raise fc_exc.InvalidSnapshotInfo(msg)

        @nova_utils.synchronized(snapshot_lock)
        def _do_pre_detach_volume(instance_url, volume_url):
            snap_infos = self.query_vm_snapshot(instance_url)
            need_del_snap = self.need_del_backup_snapshots(
                snap_infos, volume_url)
            for snap in need_del_snap:
                _def_vm_snapshot(snap.get('uri'))

        return _do_pre_detach_volume(instance_url, volume_url)

    def query_volume(self, **kwargs):
        '''query_volume

                'query_volume': ('GET',
                                 ('/volumes', kwargs.get(self.RESOURCE_URI), None, kwargs.get('id')),
                                 {'limit': kwargs.get('limit'),
                                  'offset': kwargs.get('offset'),
                                  'scope': kwargs.get('scope')
                                 },
                                 {},
                                 False),
        '''
        LOG.debug(_("[VRM-CINDER] start query_volume()"))

        uri = self.site.volume_uri + '/' + kwargs.get('id')
        response = self.get(uri)
        return response
