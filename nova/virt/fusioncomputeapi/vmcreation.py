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

import re

from nova.i18n import _
from oslo_serialization import jsonutils

from nova.virt.fusioncomputeapi import constant
from nova.virt.fusioncomputeapi import exception as fc_exc
from nova.virt.fusioncomputeapi.fcinstance import FC_INSTANCE_MANAGER as FC_MGR
from nova.virt.fusioncomputeapi import ops_task_base
from nova.virt.fusioncomputeapi import utils
from nova.virt.fusioncomputeapi.utils import LOG


class VmCreateBase(ops_task_base.OpsTaskBase):
    """vm controller class"""

    def __init__(self, fc_client, task_ops, instance):
        super(VmCreateBase, self).__init__(fc_client, task_ops)
        self._instance = instance
        self._key_data = self._instance.get('key_data')
        self._metadata = self._instance.get('metadata')

        self._vm_create_body = {}
        self._volume_ops = None
        self._location = None
        self._vifs = []
        self._block_device_info = {}
        self._root_device_name = None
        self._image_meta = {}
        self._injected_files = []
        self._admin_password = None
        self._extra_specs = {}
        self._context = {}
        self._customization = {}
        self._is_support_virtual_io = False

    def __call__(
            self,
            context,
            volume_ops,
            location,
            vifs,
            block_device_info,
            image_meta,
            injected_files,
            admin_password,
            extra_specs,
            customization,
            resource_group_urn,
            compute_ops):
        self._volume_ops = volume_ops
        self._compute_ops = compute_ops
        self._location = location
        self._vifs = vifs
        self._block_device_info = block_device_info
        self._root_device_name = block_device_info.get('root_device_name')
        self._image_meta = image_meta
        self._injected_files = injected_files
        self._admin_password = admin_password
        self._extra_specs = extra_specs
        self._context = context
        self._customization = customization
        self._resource_group_urn = resource_group_urn

    @property
    def image_properties(self):
        """image mate properties

        :return:
        """
        if self._image_meta:
            return self._image_meta.properties
        else:
            return {}

    def check_input(self):
        """check function input params

        :return:
        """
        os_option = self.get_os_options()
        LOG.debug(_('os option: %s .'), jsonutils.dumps(os_option))
        if not (os_option['osType'] and os_option['osVersion']):
            LOG.error('Invalid os option for vm %s!', self._instance['name'])
            raise fc_exc.InvalidOsOption()

    def get_body_ext(self):
        """if body not enough, child class can extend

        :return:
        """
        raise NotImplementedError()

    def build_para(self):
        """build create body"""
        if constant.CONF.fusioncompute.instance_initial_mode == 'cloud_init':
            self._key_data = None
        self._vm_create_body = {
            'name': self._instance['display_name'],
            'description': self._instance['name'],
            'group': constant.VM_GROUP_FLAG,
            'uuid': self._instance['uuid'],
            'externalUuid': self._instance['uuid'],
            'location': self._location,
            'autoBoot': self.is_auto_boot(),
            'osOptions': self.get_os_options(),
            'vmConfig': self.get_vm_config(),
            'vmCustomization': self.get_vm_customization(),
            'publickey': self._key_data
        }
        self.get_body_ext()

    def extend_ops_before_start(self):
        """vm is created in stopped state, do something before start

        :return:
        """
        pass

    def create_and_boot_vm(self):
        """create vm interface func

        :return:
        """
        self.check_input()
        self.build_para()
        self.create_vm()

        # VM is created in stopped state in some cases,
        # do the extended ops in subclass and start it at last
        if not self.is_auto_boot():
            self.inject_files()

            # Other opeation when vm stoped
            self.extend_ops_before_start()
            self._compute_ops.start_vm(self._instance, self._block_device_info)

    def get_cpu_info(self):
        """get vm cpu info"""
        cpu_info = {'quantity': self._instance['vcpus']}
        cpu_qos = utils.fc_qos_convert(self._extra_specs,
                                       constant.CPU_QOS_NOVA_KEY,
                                       constant.CPU_QOS_FC_KEY,
                                       cpu_info.get('quantity'))
        cpu_info = utils.dict_add(cpu_info, cpu_qos)

        numa_nodes = self._extra_specs.get('hw:numa_nodes', None)
        if numa_nodes is not None:
            LOG.debug(_('numa_nodes %s'), numa_nodes)
            _core_per_socket = int(self._instance['vcpus']) / int(numa_nodes)
            cpu_info['coresPerSocket'] = _core_per_socket
            LOG.debug(_('_core_per_socket %d'), _core_per_socket)

        return cpu_info

    def get_memory_info(self):
        """get vm memory info"""
        return {
            'quantityMB': self._instance['memory_mb']
        }

    def get_disks_info(self):
        """get vm disk specific info"""
        raise NotImplementedError()

    def get_nic_info(self):
        """get vm nic info"""
        return [
            {
                'name': vif['network_info']['id'],
                'portId': vif['network_info']['id'],
                'mac': vif['network_info']['address'],
                'portGroupUrn': vif['pg_urn'],
                'sequenceNum': vif['sequence_num'],
                'virtIo': 1 if self._is_support_virtual_io else 0
            }
            for vif in self._vifs
        ]

    def get_fc_os_options(self, os_type, os_version):
        """get fc options

        :param os_type:
        :param os_version:
        :return:
        """
        if os_type is None:
            os_type = ''
        if os_version is None:
            os_version = ''

        fc_os_type = constant.HUAWEI_OS_TYPE_MAP.\
            get(os_type.lower(), constant.DEFAULT_HUAWEI_OS_TYPE)

        # 201=Other_Windows(32_bit),301=Other_Linux(32_bit),401=Other(32_bit)
        # using hard code for default os_version value.
        # if huawei-os-config.conf has been changed,
        # those code should be modified also.
        if fc_os_type == 'Windows':
            fc_os_version = \
                constant.HUAWEI_OS_VERSION_INT[fc_os_type].\
                get(os_version.lower(), 201)
        elif fc_os_type == 'Linux':
            fc_os_version = \
                constant.HUAWEI_OS_VERSION_INT[fc_os_type].\
                get(os_version.lower(), 301)
        else:
            fc_os_version = \
                constant.HUAWEI_OS_VERSION_INT[fc_os_type].\
                get(os_version.lower(), 401)

        if fc_os_version in constant.VIRTUAL_IO_OS_LIST:
            self._is_support_virtual_io = True

        return {
            'osType': fc_os_type,
            'osVersion': fc_os_version
        }

    def get_os_options(self):
        """get vm os info

        get os Type from mata
        :return:
        """
        os_type = "other"
        os_version = "other"
        return self.get_fc_os_options(os_type, os_version)

    def get_properties(self):
        """get vm property"""
        vm_properties = {
            'bootOption': utils.get_boot_option_from_metadata(
                self._metadata),
            'vmVncKeymapSetting': utils.get_vnc_key_map_setting_from_metadata(
                self._metadata)}
        hpet_support = self._extra_specs.get('extra_spec:bios:hpet')
        if hpet_support is not None:
            LOG.debug(_('hpet_support %s'), hpet_support)
            if str(hpet_support).lower() == 'enabled':
                vm_properties['isHpet'] = True
        secure_vm_type = self._extra_specs.get('secuirty:instance_type')
        if secure_vm_type and str(secure_vm_type).upper() == 'GVM':
            vm_properties['secureVmType'] = 'GVM'
        elif secure_vm_type and str(secure_vm_type).upper() == 'SVM':
            vm_properties['secureVmType'] = 'SVM'

        return vm_properties

    def get_gpu_info(self):
        gpu_info = []
        enable_gpu = self._extra_specs.get('pci_passthrough:enable_gpu')
        gpu_number = self._extra_specs.get('pci_passthrough:gpu_number')
        gpu_specs = self._extra_specs.get('pci_passthrough:gpu_specs')

        if enable_gpu and str(enable_gpu).upper() == 'TRUE':
            if gpu_specs:
                gpu_specs = gpu_specs.split(':')
                if gpu_specs is None or len(gpu_specs) != 3:
                    reason = 'Invalid flavor extra spec info: ' \
                             'gpu_specs is %s' % gpu_specs
                    LOG.error(reason)
                    raise fc_exc.InvalidFlavorExtraSpecInfo(reason=reason)
                else:
                    # gpu_alias = gpu_specs[0]  # reserve property
                    gpu_mode = gpu_specs[1]
                    gpu_number = gpu_specs[2]
                    for i in range(int(gpu_number)):
                        gpu_info.append({'gpuUrn': 'auto', 'mode': gpu_mode})
                    return True, gpu_info
            elif gpu_number and int(gpu_number) > 0:
                for i in range(int(gpu_number)):
                    gpu_info.append({'gpuUrn': 'auto'})
                return True, gpu_info
            else:
                reason = 'Invalid flavor extra spec info:gpu_number is %s,' \
                         ' gpu_specs is %s' % (gpu_number, gpu_specs)
                LOG.error(reason)
                raise fc_exc.InvalidFlavorExtraSpecInfo(reason=reason)
        return False, gpu_info

    def get_vm_config(self):
        """get vm config info"""
        config = {
            'cpu': self.get_cpu_info(),
            'memory': self.get_memory_info(),
            'disks': self.get_disks_info(),
            'nics': self.get_nic_info(),
            'properties': self.get_properties()
        }

        (ret, gpu_info) = self.get_gpu_info()
        if ret:
            config['gpu'] = gpu_info
            config['memory']['reservation'] = config['memory']['quantityMB']

        # reserve cdrom mount device for vm.
        # The value None represent not reserve,
        # default is None for Uxy
        # default is xvdd for private cloud
        if constant.CONF.fusioncompute.reserve_disk_symbol is not None \
                and str(
                    constant.CONF.fusioncompute.reserve_disk_symbol).\
                        upper() == 'FALSE':
            config['cdromSequenceNum'] = constant.CONF.fusioncompute.\
                cdrom_sequence_num

        return config

    def _get_inject_ip_flag(self, port_id):
        """vnic_info:<port_uuid>":"enable_ip_inject:true|false"

        :param port_id:
        :return:
        """
        inject_ip_flag = False
        vnic_info = self._metadata.get("vnic_info:%s" % port_id)
        try:
            if isinstance(vnic_info, unicode):
                for t in vnic_info.strip().split(','):
                    if t.startswith('enable_ip_inject'):
                        flag_str = t.strip().split(':')[1]
                        flag_str = flag_str.lower()
                        inject_ip_flag = (flag_str == 'true')
        except Exception as e:
            LOG.error("network param error: %s", vnic_info)
            LOG.error("exception: %s", e)
        return inject_ip_flag

    def _get_vm_customization_nics(self):
        """get vm customization nics"""
        cus_nics = []
        for vif in self._vifs:
            if self._get_inject_ip_flag(vif['network_info']['id']) is False:
                cus_nic = {
                    'sequenceNum': vif['sequence_num'] + 1
                }
                cus_nics.append(cus_nic)
                continue

            network = vif['network_info']['network']
            subnet_ipv4_list = [s for s in network['subnets']
                                if s['version'] == constant.IPV4_VERSION]
            if len(subnet_ipv4_list) > 0:
                ip_ipv4 = None

                dns = [None, None]
                if len(subnet_ipv4_list[0]['ips']) > 0:
                    ip_ipv4 = subnet_ipv4_list[0]['ips'][0]

                dns_len = len(subnet_ipv4_list[0]['dns'])
                for index in range(0, min(2, dns_len)):
                    dns[index] = subnet_ipv4_list[0]['dns'][index]['address']

                netmask_ipv4 = str(subnet_ipv4_list[0].as_netaddr().netmask)
                gateway_ipv4 = subnet_ipv4_list[0]['gateway']['address']

                cus_nic = {'sequenceNum': vif['sequence_num'] + 1,
                           'ip': ip_ipv4 and ip_ipv4['address'] or '',
                           'gateway': gateway_ipv4,
                           'netmask': netmask_ipv4,
                           'ipVersion': constant.IPV4_VERSION,
                           'setdns': dns[0],
                           'adddns': dns[1]}
                cus_nics.append(cus_nic)

        LOG.debug(_('cus_nic: %s.'), jsonutils.dumps(cus_nics))
        return cus_nics

    def _validate_customization(self, customization):
        """_validate_customization

        :return:
        """

        valid_customizations = [
            'hostname',
            'workgroup',
            'domain',
            'domainName',
            'domainPassword',
            'ouName'
        ]

        for key in customization.keys():
            if key not in valid_customizations:
                msg = _("Invalid key: %s") % key
                raise fc_exc.InvalidCustomizationInfo(reason=msg)

    def get_vm_customization(self):
        """get vm custom info"""

        vm_custom_body = {}

        if constant.CONF.fusioncompute.instance_initial_mode == 'cloud_init':
            vm_custom_body['isUpdateVmPassword'] = False
            vm_custom_body['osType'] = self.get_os_options()['osType']
            return vm_custom_body

        inject_pwd_flag = self._metadata.get('__inject_pwd')
        if inject_pwd_flag is False or inject_pwd_flag == 'False':
            vm_custom_body['isUpdateVmPassword'] = False

        if self.get_os_options()['osType'] == 'Other':
            if len(vm_custom_body):
                return vm_custom_body
            return None

        vm_custom_body['osType'] = self.get_os_options()['osType']
        vm_custom_body['password'] = self._admin_password
        vm_custom_body['nicSpecification'] = self._get_vm_customization_nics()

        self._validate_customization(self._customization)
        for key in self._customization.keys():
            vm_custom_body[key] = self._customization[key]

        return vm_custom_body

    def is_auto_boot(self):
        """get auto boot"""
        if len(self._injected_files):
            return False
        else:
            return True

    def inject_files(self):
        """inject_files

        :return:
        """
        if constant.CONF.fusioncompute.fusioncompute_file_inject == 'disabled':
            LOG.debug(_('inject files use fusioncompute is disabled.'))
            return
        fc_vm = FC_MGR.get_vm_by_uuid(self._instance)
        for (path, contents) in self._injected_files:
            body = {
                'fileName': path,
                'vmData': contents
            }
            self.post(fc_vm.get_vm_action_uri('set_vm_data'), data=body)
            LOG.debug(_('inject file %s succeed.') % path)

    def create_vm(self):
        """create vm interface

        :return:
        """
        raise NotImplementedError()


class VmCreateByImport(VmCreateBase):
    """create vm use import vm interface

    """

    def get_protocol(self):
        """get nfs or null"""
        raise NotImplementedError()

    def create_vm(self):
        """create vm by import interface

        :return:
        """
        self.post(self.site.import_vm_uri, data=self._vm_create_body,
                  excp=fc_exc.FusionComputeReturnException, fixedInterval=1)

    def is_auto_boot(self):
        """get auto boot"""
        if len(self._injected_files):
            return False
        if self._compute_ops.get_local_disk_property(self._instance):
            return False
        else:
            return True

    def get_body_ext(self):
        """import vm extend params

        :return:
        """
        self._vm_create_body['protocol'] = self.get_protocol()
        if self._resource_group_urn:
            self._vm_create_body['resourceGroup'] = self._resource_group_urn
        if self._extra_specs:
            instance_vnic_type = self._extra_specs.get('instance_vnic:type')
            if instance_vnic_type and instance_vnic_type.lower() == 'enhanced':
                instance_vnic_bandwidth = self._extra_specs.get(
                    'instance_vnic:instance_bandwidth')
                instance_vnic_max_count = self._extra_specs.get(
                    'instance_vnic:max_count')
                if instance_vnic_bandwidth is not None \
                        and instance_vnic_max_count is not None:
                    self._vm_create_body['bandwidth'] = int(
                        instance_vnic_bandwidth)
                    self._vm_create_body['maxVnic'] = int(
                        instance_vnic_max_count)

            is_multi_disk_speedup = self._extra_specs.get(
                'extra_spec:io:persistent_grant')
            if is_multi_disk_speedup \
                    and is_multi_disk_speedup.lower() == 'true':
                self._vm_create_body[
                    'isMultiDiskSpeedup'] = is_multi_disk_speedup

    def extend_ops_before_start(self):
        """create with local disk, local disk should attach when vm stoped

        :return:
        """
        self._compute_ops.create_and_attach_local_disk_before_start(
            self._instance, self._block_device_info)


class VmCreateWithVolume(VmCreateByImport):
    """create vm with volume"""

    def get_protocol(self):
        """get null"""
        return "null"

    def get_disks_info(self):
        """override get vm disk specific info"""

        LOG.debug(_('prepare volume'))

        disks_info = []
        for disk in self._volume_ops.ensure_volume(self._block_device_info):
            disk_info = {
                'volumeUrn': disk['urn'],
                'isThin': constant.FC_DRIVER_JOINT_CFG['volume_is_thin']
            }

            if disk['mount_device'] == self._root_device_name:
                disk_info['sequenceNum'] = 1
            else:
                disk_info['sequenceNum'] = self._compute_ops.get_sequence_num(
                    disk['urn'], disk['mount_device'])

            disks_info.append(disk_info)
        return disks_info

    def get_os_options(self):
        """get vm os info"""
        if self._instance._task_state == 'rebuild_spawning':
            # os_type = self.image_properties.get(constant.HUAWEI_OS_TYPE)
            # os_version =
            # self.image_properties.get(constant.HUAWEI_OS_VERSION)
            # if os_type:
            #    return self.get_fc_os_options(os_type, os_version)
            # else:
            return super(VmCreateWithVolume, self).get_os_options()

        # get os Type from mata
        meta_data = self._volume_ops.\
            get_block_device_meta_data(self._context, self._block_device_info)
        if meta_data:
            volume_meta_data = meta_data.get('volume_image_metadata')
            if volume_meta_data:
                os_type = volume_meta_data.get(constant.HUAWEI_OS_TYPE)
                os_version = volume_meta_data.get(constant.HUAWEI_OS_VERSION)
                if os_type:
                    return self.get_fc_os_options(os_type, os_version)

        return super(VmCreateWithVolume, self).get_os_options()


class VmCreateWithImage(VmCreateByImport):
    """create vm with image"""

    def get_protocol(self):
        """default protocol is glance"""
        return "glance"

    def get_os_options(self):
        """get vm os info"""

        # get os Type from mata
        # os_type = self.image_properties.get(constant.HUAWEI_OS_TYPE)
        # os_version = self.image_properties.
        # get(constant.HUAWEI_OS_VERSION)
        # if os_type:
        #    return self.get_fc_os_options(os_type, os_version)
        # else:
        return super(VmCreateWithImage, self).get_os_options()

    def _get_image_size(self):
        """get image size info"""
        image_size = self._image_meta.size
        if image_size:
            return utils.image_size_to_gb(image_size)
        else:
            return 0

    def check_input(self):
        """create vm image detail check

        :return:
        """
        super(VmCreateWithImage, self).check_input()

        disk_quantity_gb = self._instance['root_gb']
        image_size = self._get_image_size()
        if image_size > disk_quantity_gb:
            LOG.error(_("image is larger than sys-vol."))
            raise fc_exc.ImageTooLarge

    def get_disks_info(self):
        """get image disk detail info"""

        LOG.debug(_('prepare volume'))

        disks_info = []

        # sys vol info
        sys_disk_info = {
            'sequenceNum': 1,
            'quantityGB': self._instance['root_gb'],
            'isThin': constant.FC_DRIVER_JOINT_CFG['volume_is_thin']
        }
        disks_info.append(sys_disk_info)

        # user vol info
        for disk in self._volume_ops.ensure_volume(self._block_device_info):
            user_disk_info = {
                'volumeUrn': disk['urn'],
                'sequenceNum': self._compute_ops.get_sequence_num(
                    disk['urn'],
                    disk['mount_device']),
                'isThin': constant.FC_DRIVER_JOINT_CFG['volume_is_thin']}
            disks_info.append(user_disk_info)

        return disks_info


class VmCreateWithNfsImage(VmCreateWithImage):
    """create vm with nfs image"""

    def get_protocol(self):
        """get nfs protocol"""
        return "nfs"

    def _get_template_url(self):
        """get nfs location"""
        return self.image_properties[constant.HUAWEI_IMAGE_LOCATION]

    def get_body_ext(self):
        """create vm with image, extend url info

        :return:
        """
        super(VmCreateWithNfsImage, self).get_body_ext()
        self._vm_create_body['url'] = self._get_template_url()


class VmCreateWithUdsImage(VmCreateWithImage):
    """create vm with uds image"""

    """create vm use import vm interface"""

    def __init__(self, fc_client, task_ops, instance):
        super(
            VmCreateWithUdsImage,
            self).__init__(
            fc_client,
            task_ops,
            instance)
        self.usd_image_server_ip = None
        self.usd_image_port = None
        self.usd_image_bucket_name = None
        self.usd_image_key = None

    def _get_uds_image_info(self, image_location):
        """_get_uds_image_info

        :param image_location: {ip}:{port}:{buket name}:{key}
        192.168.0.1:5443:region1.glance:001
        """

        if image_location:
            uds_image_info = image_location.strip()
            str_array = re.split(":", uds_image_info)
            if len(str_array) == 4:
                return str_array[0], \
                    str_array[1], \
                    str_array[2], \
                    str_array[3]
        reason = _("Invalid uds image info,invalid image_location!")
        raise fc_exc.InvalidUdsImageInfo(reason=reason)

    def check_input(self):
        super(VmCreateWithUdsImage, self).check_input()

        properties = self._image_meta.properties
        if properties:
            try:
                self.usd_image_server_ip,  \
                    self.usd_image_port, \
                    self.usd_image_bucket_name, \
                    self.usd_image_key = \
                    self._get_uds_image_info(
                        properties.get(constant.HUAWEI_IMAGE_LOCATION))
            except Exception:
                reason = _("Invalid uds image info,invalid loaction!")
                raise fc_exc.InvalidUdsImageInfo(reason=reason)

        if constant.CONF.fusioncompute.uds_access_key is '' \
                or constant.CONF.fusioncompute.uds_secret_key is '':
            reason = _("Invalid uds image info,invalid AK SK!")
            raise fc_exc.InvalidUdsImageInfo(reason=reason)

    def get_protocol(self):
        """get uds protocol"""
        return "uds"

    def get_body_ext(self):
        """get_body_ext

        create vm with image, extend uds info
        :return:
        """
        super(VmCreateWithUdsImage, self).get_body_ext()
        self._vm_create_body['s3Config'] = {
            'serverIp': self.usd_image_server_ip,
            'port': self.usd_image_port,
            'accessKey': constant.CONF.fusioncompute.uds_access_key,
            'secretKey': constant.CONF.fusioncompute.uds_secret_key,
            'bucketName': self.usd_image_bucket_name,
            'key': self.usd_image_key
        }


class VmCreateWithGlanceImage(VmCreateWithImage):
    """create vm with glance image"""

    def check_input(self):
        super(VmCreateWithGlanceImage, self).check_input()

        if constant.CONF.fusioncompute.glance_server_ip is '':
            reason = _("Invalid glance image info,invalid server ip!")
            raise fc_exc.InvalidGlanceImageInfo(reason=reason)

    def get_body_ext(self):
        """get_body_ext

        create vm with image, extend glance info
        :return:
        """
        super(VmCreateWithGlanceImage, self).get_body_ext()
        self._vm_create_body['glanceConfig'] = {
            'endPoint': ':'.join([str(constant.CONF.fusioncompute.host),
                                  str(constant.CONF.fusioncompute.port)]),
            'serverIp': constant.CONF.fusioncompute.glance_server_ip,
            'token': self._context.auth_token,
            'imageID': self._image_meta.id
        }


class VmCreateByClone(VmCreateBase):
    """create vm use import vm interface

    """

    def __init__(self, fc_client, task_ops, instance):
        super(VmCreateByClone, self).__init__(fc_client, task_ops, instance)
        self._need_attach_user_vols = False
        self._cloned_source_vm_or_tpl = None

    def is_auto_boot(self):
        """is_auto_boot

        :return:
        """
        if len(self._block_device_info.get('block_device_mapping')):
            self._need_attach_user_vols = True
            return False
        else:
            return super(VmCreateByClone, self).is_auto_boot()

    def get_os_options(self):
        """get vm os info"""

        # get os Type from mata
        # os_type = self.image_properties.get(constant.HUAWEI_OS_TYPE)
        # os_version = self.image_properties.get(constant.HUAWEI_OS_VERSION)
        # if os_type:
        #    return self.get_fc_os_options(os_type, os_version)
        # else:
        return super(VmCreateByClone, self).get_os_options()

    def get_disks_info(self):
        """get_disks_info

        FC itself will clone disks belonging to this tpl/vm(it should and
        must has only one sys volume).
        """
        LOG.debug(_('prepare volume'))
        disks_info = []
        disk_sequence = 1

        # sys vol info
        sys_disk_info = {
            'sequenceNum': disk_sequence,
            'quantityGB': self._instance['root_gb'],
            'isThin': constant.FC_DRIVER_JOINT_CFG['volume_is_thin']
        }
        disks_info.append(sys_disk_info)

        return disks_info

    def get_body_ext(self):
        """if body not enough, child class can extend

        :return:
        """
        if "uuid" in self._vm_create_body:
            self._vm_create_body.pop("uuid")
        self._vm_create_body["clonedVmUUID"] = self._instance['uuid']

    def extend_ops_before_start(self):
        """create by clone, user vol should attach when vm stoped

        :return:
        """
        if self._need_attach_user_vols:
            self._attach_user_vols()

    def _attach_user_vols(self):
        """_attach_user_vols

        :return:
        """
        fc_vm = FC_MGR.get_vm_by_uuid(self._instance)
        for disk in self._volume_ops.ensure_volume(self._block_device_info):
            body = {
                'volUrn': disk['urn'],
                'sequenceNum': self._compute_ops.get_sequence_num(
                    disk['urn'],
                    disk['mount_device'])}
            LOG.debug(_("begin attach user vol: %s"), disk['urn'])
            self._volume_ops.attach_volume(fc_vm, vol_config=body)

    def create_vm(self):
        self.post(self._cloned_source_vm_or_tpl.get_vm_action_uri('clone'),
                  data=self._vm_create_body,
                  excp=fc_exc.InstanceCloneFailure)


class VmCreateWithTemplate(VmCreateByClone):
    """create vm with image"""

    def check_input(self):
        super(VmCreateWithTemplate, self).check_input()

        properties = self._image_meta.properties
        if properties:
            try:
                self._cloned_source_vm_or_tpl = \
                    self._get_vm_by_template_url(
                        properties.get(constant.HUAWEI_IMAGE_LOCATION))
                self._validate_template(self._cloned_source_vm_or_tpl)
            except Exception:
                LOG.error(_("Invalid FusionCompute template !"))
                raise fc_exc.InstanceCloneFailure

    def get_body_ext(self):
        """if body not enough, child class can extend

        :return:
        """
        super(VmCreateWithTemplate, self).get_body_ext()
        self._vm_create_body['isTemplate'] = False

        is_link_clone = self._metadata.get(constant.HUAWEI_IS_LINK_CLONE)
        if is_link_clone:
            self._vm_create_body['isLinkClone'] = is_link_clone

    def _get_vm_by_template_url(self, template_url):
        """_get_vm_by_template_url

        :param template_url: {vrm site id}:{vm id}
        239d8a8e:i-00000061
        """

        vm_id = None
        if template_url:
            url = template_url.strip()
            str_array = re.split(":", url)
            if len(str_array) == 2:
                vm_id = str_array[1]

        if vm_id is not None:
            return FC_MGR.get_vm_by_id(vm_id)
        return None

    def _validate_template(self, instance):
        """_validate_template

        :param instance: fc vm
        :return:
        """
        if instance is not None and instance.isTemplate is not True:
            raise fc_exc.InstanceCloneFailure

        for disk in instance['vmConfig']['disks']:
            if disk['sequenceNum'] not in [0, 1]:
                raise fc_exc.InstanceCloneFailure


def get_vm_create(fc_client, task_ops, instance, image_meta=None):
    """get create vm object"""
    vm_class = VmCreateWithGlanceImage

    return vm_class(fc_client, task_ops, instance)
