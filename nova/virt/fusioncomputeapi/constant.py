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

import json
import re
from oslo_config import cfg
import types

from nova.compute import power_state
from oslo_log import log as logging
from nova.i18n import _

from nova.virt.fusioncomputeapi import osconfig


LOG = logging.getLogger(__name__)
CONF = cfg.CONF


fusion_compute_opts = [
    cfg.StrOpt('fc_user',
               default='',
               help='FusionCompute user name'),
    cfg.StrOpt('fc_pwd',
               default='',
               help='FusionCompute user password',
               secret=True),
    cfg.StrOpt('fc_ip',
               default=None,
               help='Management IP of FusionCompute'),
    cfg.StrOpt('fc_image_path',
               default=None,
               help='NFS Image server path'),
    cfg.StrOpt('vxlan_dvs_name',
               default=None,
               help='FusionCompute dvswitch name for vxlan network'),
    cfg.StrOpt('enhanced_network_dvs_name',
               default=None,
               help='FusionCompute dvs_name for enhanced_network network'),
    cfg.BoolOpt('use_admin_pass',
                default=False,
                help='Create vm using the admin pass or fusionCompute pass'),
    cfg.StrOpt('clusters',
               default='',
               help='FusionCompute clusters mapped to hypervisors'),
    cfg.FloatOpt('cpu_ratio',
                 default=1,
                 help='FusionCompute cpu multiplexing ratio'),
    cfg.StrOpt('glance_server_ip',
               default=None,
               help='FusionSphere glance server ip'),
    cfg.StrOpt('uds_access_key',
               default=None,
               help='FusionCompute uds image access key',
               secret=True),
    cfg.StrOpt('uds_secret_key',
               default=None,
               help='FusionCompute uds image secret key',
               secret=True),
    cfg.StrOpt('instance_initial_mode',
               default='FusionCompute',
               help='Instance initial mode which is cloud_init or FusionCompute'),
    cfg.IntOpt('resource_reduced_rate',
               default=100,
               help='Resource reduced rate for cpu and memory in FusionCompute'),
    cfg.StrOpt('reserve_disk_symbol',
               default='True',
               help='Reserve b/c/d disk symbol in FusionCompute.'),
    cfg.StrOpt('fusioncompute_file_inject',
               default='enabled',
               help='Use file inject by FusionCompute'),
    cfg.IntOpt('cdrom_sequence_num',
               default=0,
               help='cdrom letter in FusionCompute'),
    cfg.IntOpt('cpu_usage_monitor_period',
               default=3600,
               help='FusionCompute cpu usage monitor period'),
    cfg.IntOpt('workers',
               default=4,
               help='FusionCompute compute process number'),
    cfg.IntOpt('fc_request_timeout_max',
               default=3600,
               help='FusionCompute request timeout max'),
    cfg.IntOpt('fc_request_timeout_min',
               default=300,
               help='FusionCompute request timeout min'),
    cfg.IntOpt('attach_int_timeout',
               default=90,
               help='Attach interface timeout'),
    cfg.IntOpt('safe_stop_vm_timeout',
               default=600,
               help='Safe stop vm timeout'),
    cfg.IntOpt('fc_request_timeout_delete_vm',
               default=36000,
               help='FusionCompute request timeout delete vm'),
    cfg.IntOpt('fc_request_timeout_delete_vm_timelimited',
               default=30000,
               help='FusionCompute request timeout delete vm'),
    cfg.BoolOpt('enable_virtualio',
                default=False,
                help='Vm virtual IO'),
    cfg.BoolOpt('enable_snapshot_auto_del',
                default=False,
                help='enable backup snapshot auto delete before volume detach'),
    cfg.StrOpt('host',
               default="",
               help='glance host'),
    cfg.StrOpt('port',
               default="",
               help='glance port')
]

CONF.register_opts(fusion_compute_opts, group='fusioncompute')

virt_opts = [
    cfg.BoolOpt('use_kbox',
                default=False,
                help='use kbox in libvirt'),
    cfg.BoolOpt('local_resume_instance',
                default=True,
                help='Auto start the instance when stop itself')
]

CONF.register_opts(virt_opts)

FC_DRIVER_JOINT_CFG = {
    'user_type': '2',
    'fc_port': 7443,
    'api_version': '6.0',
    'hypervisor_version': 60,
    'hypervisor_type': 'FusionCompute',
    'request_time_out': 120,
    'dvs_mapping': 'physnet1:service',
    'volume_is_thin': True
}


def str_to_bool(cver_str):
    """convert string to boolean

    :param cver_str: string should to convert
    :return: Boolean
    """
    if isinstance(cver_str, types.BooleanType):
        return cver_str
    elif isinstance(cver_str, types.StringType):
        bool_map = {'true': True, 'false': False}
        bool_str = cver_str.lower() if cver_str else ""
        if bool_str not in bool_map:
            raise ValueError('%s is not valid boolean.' % cver_str)
        else:
            return bool_map[bool_str]
    else:
        raise ValueError('%s is not valid boolean.' % cver_str)


class Enum(dict):
    """enum object

    """

    def __init__(self, **enums):
        super(Enum, self).__init__()
        for key in enums:
            self[key] = enums[key]

    def __getattr__(self, name):
        return self.get(name)

CONFIG_ITEM_TYPE = Enum(STR=0,
                        INT=1,
                        BOOL=2)

# ignore pylint:disable=R0903


class ConfigItemValue(object):
    """fc config detail item

    """

    def __init__(self, key, value, conf_type=CONFIG_ITEM_TYPE.STR):
        self.key = key
        self.value = value
        self.conf_type = conf_type
        if conf_type is None:
            raise TypeError('item %s set value %s type eror.' % (key, value))

    def set_value(self, value):
        """set item value basis by type

        """
        if self.conf_type == CONFIG_ITEM_TYPE.STR:
            self.value = str(value)
        elif self.conf_type == CONFIG_ITEM_TYPE.INT:
            try:
                int_value = int(value)
                self.value = int_value
            except ValueError:
                LOG.error(_("%s config to int fail."), str(value))
        elif self.conf_type == CONFIG_ITEM_TYPE.BOOL:
            try:
                bool_value = str_to_bool(value)
                self.value = bool_value
            except ValueError:
                LOG.error(_("%s config to bool fail."), str(value))
        else:
            LOG.error(_("config type %s is error."), self.conf_type)


class FcConfig(dict):
    """fc config file manager

    """

    def __init__(self, cfg_path, default_value):
        super(FcConfig, self).__init__()
        for key, value in default_value.items():
            self[key] = value

        for key, value in json.load(open(cfg_path, 'r')).items():
            if self.get(key):
                self[key].set_value(value)
            else:
                LOG.error(_("%s not exists in config."), key)

    def __getattr__(self, name):
        if self.get(name):
            return self.get(name).value
        else:
            return None

#================CONFIG constant begin========================
FC_PLUG_CONFIG_PATH = '/etc/nova/fc-nova-compute'

TEMPLATE_VHD_SIZE = 1024
TEMPLATE_VHD_FILE = '%s/template.vhd' % FC_PLUG_CONFIG_PATH

OS_CONFIG_FILE = '%s/huawei-os-config.conf' % FC_PLUG_CONFIG_PATH
VIRTUAL_IO_OS_CONFIG_FILE = '%s/virtualio-os-config.conf' % FC_PLUG_CONFIG_PATH

FC_DRIVER_DEFAULT_CFG = {
    'fc_user': ConfigItemValue('fc_user', ''),
    'fc_pwd': ConfigItemValue('fc_pwd', ''),
    'fc_ip': ConfigItemValue('fc_ip', None),
    'user_type': ConfigItemValue('user_type', 2, CONFIG_ITEM_TYPE.INT),
    'fc_port': ConfigItemValue('fc_port', 7443, CONFIG_ITEM_TYPE.INT),
    'api_version': ConfigItemValue('api_version', '6.0'),
    'hypervisor_version': ConfigItemValue('hypervisor_version', 60,
                                          CONFIG_ITEM_TYPE.INT),
    'hypervisor_type': ConfigItemValue('hypervisor_type', 'FusionCompute'),
    'fc_image_path': ConfigItemValue('fc_image_path', None),
    'dvs_vxlan': ConfigItemValue('dvs_vxlan', None),
    'cluster': ConfigItemValue('cluster', None),
    'dvs_mapping': ConfigItemValue('dvs_mapping', 'physnet1:service'),
    'request_time_out': ConfigItemValue('request_time_out', 120,
                                        CONFIG_ITEM_TYPE.INT),
    'gen_admin_pass': ConfigItemValue('gen_admin_pass', False,
                                      CONFIG_ITEM_TYPE.BOOL),
    'volume_is_thin': ConfigItemValue('volume_is_thin', True,
                                      CONFIG_ITEM_TYPE.BOOL),
    'clusters': ConfigItemValue('clusters', ''),
    'cpu_rate': ConfigItemValue('cpu_rate', 1, CONFIG_ITEM_TYPE.INT),
    'glance_server_ip': ConfigItemValue('glance_server_ip', None),
    'uds_access_key': ConfigItemValue('uds_access_key', None),
    'uds_secret_key': ConfigItemValue('uds_secret_key', None),
    'cpu_usage_monitor_period': ConfigItemValue('cpu_usage_monitor_period',
                                                60 * 60, CONFIG_ITEM_TYPE.INT)
}

FC_PLUG_CONFIG_FILE = '%s/fc-nova-compute.conf' % FC_PLUG_CONFIG_PATH
"""FC_CONF = FcConfig(FC_PLUG_CONFIG_FILE, FC_DRIVER_DEFAULT_CFG)

"""


#============================vm constant begin===============

VM_GROUP_FLAG = 'FSP'

VM_STATUS = Enum(UNKNOWN='unknown', RUNNING='running',
                 STOPPED='stopped', STOPPING='stopping',
                 PAUSED='pause', SUSPENDED='hibernated',
                 MIGRATING='migrating',
                 FAULTRESUMING='fault-resuming')

NOTIFY_NEUTRON = Enum(FALSE='false',
                      TRUE='true')

PV_STATUS = Enum(STARTING='starting', RUNNING='running',
                 NOTRUNNING='notRunning')

VM_POWER_STATE_MAPPING = {
    VM_STATUS.UNKNOWN: power_state.NOSTATE,
    VM_STATUS.RUNNING: power_state.RUNNING,
    VM_STATUS.PAUSED: power_state.PAUSED,
    VM_STATUS.STOPPING: power_state.SHUTDOWN,
    VM_STATUS.STOPPED: power_state.SHUTDOWN,
    VM_STATUS.SUSPENDED: power_state.SUSPENDED
}

FC_RETURN_ERROR = "FusionCompute return failed."

REBOOT_TYPE = Enum(SOFT='SOFT', HARD='HARD')
FC_REBOOT_TYPE = {
    REBOOT_TYPE.HARD: 'force',
    REBOOT_TYPE.SOFT: 'safe'
}

HUAWEI_OS_TYPE = '__os_type'
HUAWEI_OS_VERSION = '__os_version'
HUAWEI_IMAGE_LOCATION = '__image_location'
HUAWEI_IMAGE_TYPE = '__image_source_type'
HUAWEI_IS_LINK_CLONE = '__linked_clone'

HUAWEI_OS_TYPE_MAP = {
    'windows': 'Windows',
    'linux': 'Linux',
    'other': 'Other'
}

DEFAULT_HUAWEI_OS_TYPE = 'Other'
DEFAULT_HUAWEI_OS_VERSION = 'Other(32 bit)'

# ComputeOps._init_os_config() will do real initialization
DEFAULT_HUAWEI_OS_CONFIG = ['', '']

HUAWEI_OS_VERSION_INT = osconfig.OS_VERSION_INT
HUAWEI_OS_VERSION_STR = osconfig.OS_VERSION_STR
HUAWEI_VIRTUAL_IO_OS_VERSION_INT = osconfig.VIRTUAL_IO_OS_VERSION_INT
VIRTUAL_IO_OS_LIST = []

BOOT_OPTION_MAP = {
    'hd': 'disk',
    'hd,network': 'disk',
    'network': 'pxe',
    'network,hd': 'pxe',
    'default': 'disk'
}

VNC_KEY_MAP_SETTING = {
    'en-us': 7,
    'de': 4,
    'fr': 12,
    'ru': 30,
    'es': 8,
    'default': 7
}

IPV4_VERSION = 4

DRS_RULES_TYPE_MAP = {
    'affinity': 1,
    'anti-affinity': 2
}

DRS_RULES_OP_TYPE_MAP = {
    'delete': 0,
    'modify': 1,
    'create': 2
}

#=================uri constant begin================
VM_URI_MAP = {
    'start': '/action/start',
    'stop': '/action/stop',
    'reboot': '/action/reboot',
    'pause': '/action/pause',
    'unpause': '/action/resume',
    'import': '/action/import',
    'export': '/action/export',
    'unresume': '/action/unresume',
    'migrate': '/action/migrate',
    'clone': '/action/clone',
    'set_vm_data': '/action/uploadVmData',
    'attachvol': '/action/attachvol',
    'detachvol': '/action/detachvol',
    'expandvol': '/action/expandvol',
    'suspend': '/action/hibernate',
    'attach_gpu': '/action/attachgpu',
    'detach_gpu': '/action/detachgpu',
    'nics': '/virtualNics'
}

VOL_URI_MAP = {
    'modio': '/modifyIOpropertyOfVolume'
}

FC_SITE_URI_MAP = {
    'vm_uri': {
        'baseuri': '%(site_uri)s/vms'
    },

    'import_vm_uri': {
        'baseuri': '%(vm_uri)s/action/import',
        'dependuri': ['vm_uri']
    },
    'cluster_uri': {
        'baseuri': '%(site_uri)s/clusters'
    },
    'host_uri': {
        'baseuri': '%(site_uri)s/hosts'
    },
    'datastore_uri': {
        'baseuri': '%(site_uri)s/datastores'
    },
    'volume_uri': {
        'baseuri': '%(site_uri)s/volumes'
    },
    'dvswitchs_uri': {
        'baseuri': '%(site_uri)s/dvswitchs'
    },
    'current_time_uri': {
        'baseuri': '%(site_uri)s/monitors/getSysCurrentTime'
    },
    'metric_curvedata_uri': {
        'baseuri': '%(site_uri)s/monitors/objectmetric-curvedata'
    }

}

TOKEN_URI = '/service/session'
SITE_URI = '/service/sites'

#=================network====================
TYPE_FNC = 2
TYPE_VLAN = 'vlan'
TYPE_VXLAN = 'vxlan'
TYPE_FLAT = 'flat'

DVSWITCHS = 'dvSwitchs'
DVS_URI = '/dvswitchs'
PORT_GROUP_URI = DVS_URI + '/%(dvs_id)s/portgroups'
PORT_GROUP_ID_URI = PORT_GROUP_URI + '/%(pg_id)s'
VSP_URI = DVS_URI + '/%(dvs_id)s/vsps'

VSP_TAG_KEY = 'NeutronPort'

#=================other====================
ID_IN_URN_REGEX = re.compile(r':(?P<id>[^:]+)$')
CPU_QOS_NOVA_KEY = ['quota:cpu_shares',
                    'quota:cpu_limit',
                    'quota:cpu_reserve']
CPU_QOS_FC_KEY = ['weight',
                  'limit',
                  'reservation']
CPU_QOS_FC_DEFAULT_VALUE = [1000, 0, 0]

MOUNT_DEVICE_SEQNUM_MAP = {
    '/dev/sda': 1, '/dev/vda': 1, '/dev/xvda': 1,
    '/dev/sdb': 2, '/dev/vdb': 2, '/dev/xvdb': 2,
    '/dev/sdc': 3, '/dev/vdc': 3, '/dev/xvdc': 3,
    '/dev/sdd': 4, '/dev/vdd': 4, '/dev/xvdd': 4,
    '/dev/sde': 5, '/dev/vde': 5, '/dev/xvde': 5,
    '/dev/sdf': 6, '/dev/vdf': 6, '/dev/xvdf': 6,
    '/dev/sdg': 7, '/dev/vdg': 7, '/dev/xvdg': 7,
    '/dev/sdh': 8, '/dev/vdh': 8, '/dev/xvdh': 8,
    '/dev/sdi': 9, '/dev/vdi': 9, '/dev/xvdi': 9,
    '/dev/sdj': 10, '/dev/vdj': 10, '/dev/xvdj': 10,
    '/dev/sdk': 11, '/dev/vdk': 11, '/dev/xvdk': 11,
    '/dev/sdl': 12, '/dev/vdl': 12, '/dev/xvdl': 12,
    '/dev/sdm': 13, '/dev/vdm': 13, '/dev/xvdm': 13,
    '/dev/sdn': 14, '/dev/vdn': 14, '/dev/xvdn': 14,
    '/dev/sdo': 15, '/dev/vdo': 15, '/dev/xvdo': 15,
    '/dev/sdp': 16, '/dev/vdp': 16, '/dev/xvdp': 16,
    '/dev/sdq': 17, '/dev/vdq': 17, '/dev/xvdq': 17,
    '/dev/sdr': 18, '/dev/vdr': 18, '/dev/xvdr': 18,
    '/dev/sds': 19, '/dev/vds': 19, '/dev/xvds': 19,
    '/dev/sdt': 20, '/dev/vdt': 20, '/dev/xvdt': 20,
    '/dev/sdu': 21, '/dev/vdu': 21, '/dev/xvdu': 21,
    '/dev/sdv': 22, '/dev/vdv': 22, '/dev/xvdv': 22,
    '/dev/sdw': 23, '/dev/vdw': 23, '/dev/xvdw': 23,
    '/dev/sdx': 24, '/dev/vdx': 24, '/dev/xvdx': 24,
    '/dev/sdy': 25, '/dev/vdy': 25, '/dev/xvdy': 25,
    '/dev/sdz': 26, '/dev/vdz': 26, '/dev/xvdz': 26,
    '/dev/sdaa': 27, '/dev/vdaa': 27, '/dev/xvdaa': 27,
    '/dev/sdab': 28, '/dev/vdab': 28, '/dev/xvdab': 28,
    '/dev/sdac': 29, '/dev/vdac': 29, '/dev/xvdac': 29,
    '/dev/sdad': 30, '/dev/vdad': 30, '/dev/xvdad': 30,
    '/dev/sdae': 31, '/dev/vdae': 31, '/dev/xvdae': 31,
    '/dev/sdaf': 32, '/dev/vdaf': 32, '/dev/xvdaf': 32,
    '/dev/sdag': 33, '/dev/vdag': 33, '/dev/xvdag': 33,
    '/dev/sdah': 34, '/dev/vdah': 34, '/dev/xvdah': 34,
    '/dev/sdai': 35, '/dev/vdai': 35, '/dev/xvdai': 35,
    '/dev/sdaj': 36, '/dev/vdaj': 36, '/dev/xvdaj': 36,
    '/dev/sdak': 37, '/dev/vdak': 37, '/dev/xvdak': 37,
    '/dev/sdal': 38, '/dev/vdal': 38, '/dev/xvdal': 38,
    '/dev/sdam': 39, '/dev/vdam': 39, '/dev/xvdam': 39,
    '/dev/sdan': 40, '/dev/vdan': 40, '/dev/xvdan': 40,
    '/dev/sdao': 41, '/dev/vdao': 41, '/dev/xvdao': 41,
    '/dev/sdap': 42, '/dev/vdap': 42, '/dev/xvdap': 42,
    '/dev/sdaq': 43, '/dev/vdaq': 43, '/dev/xvdaq': 43,
    '/dev/sdar': 44, '/dev/vdar': 44, '/dev/xvdar': 44,
    '/dev/sdas': 45, '/dev/vdas': 45, '/dev/xvdas': 45,
    '/dev/sdat': 46, '/dev/vdat': 46, '/dev/xvdat': 46,
    '/dev/sdau': 47, '/dev/vdau': 47, '/dev/xvdau': 47,
    '/dev/sdav': 48, '/dev/vdav': 48, '/dev/xvdav': 48,
    '/dev/sdaw': 49, '/dev/vdaw': 49, '/dev/xvdaw': 49,
    '/dev/sdax': 50, '/dev/vdax': 50, '/dev/xvdax': 50,
    '/dev/sday': 51, '/dev/vday': 51, '/dev/xvday': 51,
    '/dev/sdaz': 52, '/dev/vdaz': 52, '/dev/xvdaz': 52,
    '/dev/sdba': 53, '/dev/vdba': 53, '/dev/xvdba': 53,
    '/dev/sdbb': 54, '/dev/vdbb': 54, '/dev/xvdbb': 54,
    '/dev/sdbc': 55, '/dev/vdbc': 55, '/dev/xvdbc': 55,
    '/dev/sdbd': 56, '/dev/vdbd': 56, '/dev/xvdbd': 56,
    '/dev/sdbe': 57, '/dev/vdbe': 57, '/dev/xvdbe': 57,
    '/dev/sdbf': 58, '/dev/vdbf': 58, '/dev/xvdbf': 58,
    '/dev/sdbg': 59, '/dev/vdbg': 59, '/dev/xvdbg': 59,
    '/dev/sdbh': 60, '/dev/vdbh': 60, '/dev/xvdbh': 60,
    '/dev/sdbi': 61, '/dev/vdbi': 61, '/dev/xvdbi': 61,
    '/dev/sdbj': 62, '/dev/vdbj': 62, '/dev/xvdbj': 62,
    '/dev/sdbk': 63, '/dev/vdbk': 63, '/dev/xvdbk': 63,
    '/dev/sdbl': 64, '/dev/vdbl': 64, '/dev/xvdbl': 64,
    '/dev/sdbm': 65, '/dev/vdbm': 65, '/dev/xvdbm': 65
}

MOUNT_DEVICE_SEQNUM_MAP_IDE = {
    '/dev/sda': 1, '/dev/vda': 1, '/dev/xvda': 1,
    '/dev/sdb': 1001, '/dev/vdb': 1001, '/dev/xvdb': 1001,
    '/dev/sdc': 1002, '/dev/vdc': 1002, '/dev/xvdc': 1002,
    '/dev/sdd': 1003, '/dev/vdd': 1003, '/dev/xvdd': 1003,
    '/dev/sde': 2, '/dev/vde': 2, '/dev/xvde': 2,
    '/dev/sdf': 3, '/dev/vdf': 3, '/dev/xvdf': 3,
    '/dev/sdg': 4, '/dev/vdg': 4, '/dev/xvdg': 4,
    '/dev/sdh': 5, '/dev/vdh': 5, '/dev/xvdh': 5,
    '/dev/sdi': 6, '/dev/vdi': 6, '/dev/xvdi': 6,
    '/dev/sdj': 7, '/dev/vdj': 7, '/dev/xvdj': 7,
    '/dev/sdk': 8, '/dev/vdk': 8, '/dev/xvdk': 8,
    '/dev/sdl': 9, '/dev/vdl': 9, '/dev/xvdl': 9,
    '/dev/sdm': 10, '/dev/vdm': 10, '/dev/xvdm': 10,
    '/dev/sdn': 11, '/dev/vdn': 11, '/dev/xvdn': 11,
    '/dev/sdo': 12, '/dev/vdo': 12, '/dev/xvdo': 12,
    '/dev/sdp': 13, '/dev/vdp': 13, '/dev/xvdp': 13,
    '/dev/sdq': 14, '/dev/vdq': 14, '/dev/xvdq': 14,
    '/dev/sdr': 15, '/dev/vdr': 15, '/dev/xvdr': 15,
    '/dev/sds': 16, '/dev/vds': 16, '/dev/xvds': 16,
    '/dev/sdt': 17, '/dev/vdt': 17, '/dev/xvdt': 17,
    '/dev/sdu': 18, '/dev/vdu': 18, '/dev/xvdu': 18,
    '/dev/sdv': 19, '/dev/vdv': 19, '/dev/xvdv': 19,
    '/dev/sdw': 20, '/dev/vdw': 20, '/dev/xvdw': 20,
    '/dev/sdx': 21, '/dev/vdx': 21, '/dev/xvdx': 21,
    '/dev/sdy': 22, '/dev/vdy': 22, '/dev/xvdy': 22,
    '/dev/sdz': 1004, '/dev/vdz': 1004, '/dev/xvdz': 1004,
    '/dev/sdaa': 23, '/dev/vdaa': 23, '/dev/xvdaa': 23,
    '/dev/sdab': 24, '/dev/vdab': 24, '/dev/xvdab': 24,
    '/dev/sdac': 25, '/dev/vdac': 25, '/dev/xvdac': 25,
    '/dev/sdad': 26, '/dev/vdad': 26, '/dev/xvdad': 26,
    '/dev/sdae': 27, '/dev/vdae': 27, '/dev/xvdae': 27,
    '/dev/sdaf': 28, '/dev/vdaf': 28, '/dev/xvdaf': 28,
    '/dev/sdag': 29, '/dev/vdag': 29, '/dev/xvdag': 29,
    '/dev/sdah': 30, '/dev/vdah': 30, '/dev/xvdah': 30,
    '/dev/sdai': 31, '/dev/vdai': 31, '/dev/xvdai': 31,
    '/dev/sdaj': 32, '/dev/vdaj': 32, '/dev/xvdaj': 32,
    '/dev/sdak': 33, '/dev/vdak': 33, '/dev/xvdak': 33,
    '/dev/sdal': 34, '/dev/vdal': 34, '/dev/xvdal': 34,
    '/dev/sdam': 35, '/dev/vdam': 35, '/dev/xvdam': 35,
    '/dev/sdan': 36, '/dev/vdan': 36, '/dev/xvdan': 36,
    '/dev/sdao': 37, '/dev/vdao': 37, '/dev/xvdao': 37,
    '/dev/sdap': 38, '/dev/vdap': 38, '/dev/xvdap': 38,
    '/dev/sdaq': 39, '/dev/vdaq': 39, '/dev/xvdaq': 39,
    '/dev/sdar': 40, '/dev/vdar': 40, '/dev/xvdar': 40,
    '/dev/sdas': 41, '/dev/vdas': 41, '/dev/xvdas': 41,
    '/dev/sdat': 42, '/dev/vdat': 42, '/dev/xvdat': 42,
    '/dev/sdau': 43, '/dev/vdau': 43, '/dev/xvdau': 43,
    '/dev/sdav': 44, '/dev/vdav': 44, '/dev/xvdav': 44,
    '/dev/sdaw': 45, '/dev/vdaw': 45, '/dev/xvdaw': 45,
    '/dev/sdax': 46, '/dev/vdax': 46, '/dev/xvdax': 46,
    '/dev/sday': 47, '/dev/vday': 47, '/dev/xvday': 47,
    '/dev/sdaz': 48, '/dev/vdaz': 48, '/dev/xvdaz': 48,
    '/dev/sdba': 49, '/dev/vdba': 49, '/dev/xvdba': 49,
    '/dev/sdbb': 50, '/dev/vdbb': 50, '/dev/xvdbb': 50,
    '/dev/sdbc': 51, '/dev/vdbc': 51, '/dev/xvdbc': 51,
    '/dev/sdbd': 52, '/dev/vdbd': 52, '/dev/xvdbd': 52,
    '/dev/sdbe': 53, '/dev/vdbe': 53, '/dev/xvdbe': 53,
    '/dev/sdbf': 54, '/dev/vdbf': 54, '/dev/xvdbf': 54,
    '/dev/sdbg': 55, '/dev/vdbg': 55, '/dev/xvdbg': 55,
    '/dev/sdbh': 56, '/dev/vdbh': 56, '/dev/xvdbh': 56,
    '/dev/sdbi': 57, '/dev/vdbi': 57, '/dev/xvdbi': 57,
    '/dev/sdbj': 58, '/dev/vdbj': 58, '/dev/xvdbj': 58,
    '/dev/sdbk': 59, '/dev/vdbk': 59, '/dev/xvdbk': 59,
    '/dev/sdbl': 60, '/dev/vdbl': 60, '/dev/xvdbl': 60,
    '/dev/sdbm': 61, '/dev/vdbm': 61, '/dev/xvdbm': 61
}

FUSIONCOMPUTE_MAX_VOLUME_NUM = 11
