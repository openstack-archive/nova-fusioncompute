"""
    API of Network Resource on FusionCompute
"""

import json
import types
import re
import time

from nova import exception
from neutronclient.common import exceptions as neutron_client_exc

from nova import context as nova_ctxt
from nova.i18n import _
from oslo_serialization import jsonutils
#from nova.network import api as neutron_api
from nova.network.neutronv2 import api as neutron_api
from nova.virt.fusioncomputeapi import exception as fc_exc
from nova.virt.fusioncomputeapi import ops_task_base
from nova.virt.fusioncomputeapi import utils
from nova.virt.fusioncomputeapi.utils import LOG
from nova.virt.fusioncomputeapi import constant

class PortGroupAdapter(dict):
    """
    Port group class

    """
    def _make_pg_name(self, network, dvs_id):
        """
        create pg name info
        :param network:
        :return:
        """
        return '#'.join([network['name'], network['id'], dvs_id])

    def _make_pg_name_suffix(self, network, dvs_id, suffix):
        """
        create pg name info
        :param network:
        :return:
        """

        return '#'.join([network['name'], network['id'], dvs_id, suffix])

    def __init__(self, network):
        super(PortGroupAdapter, self).__init__()

        self['vlanId'] = None
        self['vxlanId'] = None
        self['isCalcTCPCheckSum'] = False
        if network['provider:network_type'] == constant.TYPE_VLAN:
            self['vlanId'] = network['provider:segmentation_id']
        elif network['provider:network_type'] == constant.TYPE_VXLAN:
            self['vxlanId'] = network['provider:segmentation_id']
        elif network['provider:network_type'] == constant.TYPE_FLAT:
            self['vlanId'] = 0

    def __getattr__(self, name):
        return self.get(name)

    def to_json(self):
        """
        change dict to json format
        """
        return jsonutils.dumps(self)

class PortGroupQueryAdapter(PortGroupAdapter):
    """PortGroupQueryAdapter
    """

    def __init__(self, network, dvs_id):
        super(PortGroupQueryAdapter, self).__init__(network)
        self['names'] = [self._make_pg_name(network, dvs_id)]

class PortGroupSuffixQueryAdapter(PortGroupAdapter):
    """PortGroupQueryAdapter
    """

    def __init__(self, network, dvs_id, suffix):
        super(PortGroupSuffixQueryAdapter, self).__init__(network)

        self['names'] = [self._make_pg_name_suffix(network, dvs_id, suffix)]
        self['isCalcTCPCheckSum'] = True

class PortGroupCreateAdapter(PortGroupAdapter):
    """PortGroupCreateAdapter
    """

    def __init__(self, network, dvs_id):
        super(PortGroupCreateAdapter, self).__init__(network)

        self['name'] = self._make_pg_name(network, dvs_id)

class PortGroupSuffixCreateAdapter(PortGroupAdapter):
    """PortGroupCreateAdapter
    """

    def __init__(self, network, dvs_id, suffix):
        super(PortGroupSuffixCreateAdapter, self).__init__(network)

        self['name'] = self._make_pg_name_suffix(network, dvs_id, suffix)
        self['isCalcTCPCheckSum'] = True

class NetworkOps(ops_task_base.OpsTaskBase):
    """
    network operation class

    """
    def __init__(self, fc_client, task_ops):
        super(NetworkOps, self).__init__(fc_client, task_ops)
        self._neutron = neutron_api.API()
        self.dvs_mapping = {}
        self.physnet_mapping = {}
        self._init_all_fc_dvs()

    def _get_dvs_id_by_dvs_name(self, dvs_name=None):
        """
        get dvswitch id from cache according to physical network name

        :param dvs_name:
        :return:
        """
        if dvs_name is None:
            return None

        LOG.debug(_("physnet_name is %s"), dvs_name)

        dvs_id = self.dvs_mapping.get(dvs_name)
        if not dvs_id:
            self._init_all_fc_dvs()
        else:
            if not self._is_dvs_in_hypervisor(dvs_id):
                self._init_all_fc_dvs()

        return self.dvs_mapping.get(dvs_name)

    def _get_dvs_id_by_physnet_name(self, physnet_name):

        if physnet_name is None:
            return None

        dvs_ids = self.physnet_mapping.get(physnet_name)

        if not dvs_ids:
            self._init_all_fc_dvs()
        else:
            if not self._is_dvs_in_hypervisor(dvs_ids[0]):
                self._init_all_fc_dvs()

        return self.physnet_mapping.get(physnet_name)[0] if self.physnet_mapping.get(physnet_name) else None

    def _is_dvs_in_hypervisor(self, id):
        try:
            dvs = self.get('%s/%s' % (self.site.dvswitchs_uri, str(id)))
            if 'urn' not in dvs:
                return False
        except Exception:
            return False
        return True

    def _init_all_fc_dvs(self):
        """
        Send message to fc and get dvswitch info

        :return:
        """
        LOG.debug("loading dvs mapping ")
        dvs_map_temp = {}
        physnet_map_temp = {}
        data = self.get(self.site.dvswitchs_uri)
        if not data.get(constant.DVSWITCHS):
            raise fc_exc.DVSwitchNotFound()

        dvs = data.get(constant.DVSWITCHS)
        if dvs and len(dvs) > 0:
            for dvswitch in dvs:
                dvs_id = utils.get_id_from_urn(dvswitch.get('urn'))
                dvs_map_temp[dvswitch["name"]] = dvs_id
                self.update_physnet_map(dvs_id, physnet_map_temp)

        LOG.debug("init all fc dvs dvs map is %s, physnet map is %s", jsonutils.dumps(dvs_map_temp), jsonutils.dumps(physnet_map_temp))
        self.dvs_mapping = dvs_map_temp
        self.physnet_mapping = physnet_map_temp

    def update_physnet_map(self, dvs_id, physnet_map_temp):

        dvs = self.get('%s/%s' % (self.site.dvswitchs_uri, str(dvs_id)))
        dvs['params']['physnetName'] = dvs.get('name')
        if dvs:
            # leave out enhanced network dvs by name
            if dvs.get('name') == constant.CONF.fusioncompute.enhanced_network_dvs_name:
                return
            if dvs.get('params') and dvs.get('params').get('physnetName'):
                physnet_name = dvs.get('params').get('physnetName')
                if physnet_map_temp.get(physnet_name):
                    physnet_map_temp.get(physnet_name).append(dvs_id)
                else:
                    physnet_map_temp[physnet_name] = [dvs_id]

    def _get_network_from_neutron(self, context, network_info):
        """
        send message to neutron server to get network information

        :param context:
        :param network_info:
        :return:
        """
        client = neutron_api.get_client(context)
        try:
            network = client.show_network(network_info['id']).get('network') or {}
        except neutron_client_exc.NetworkNotFoundClient:
            raise exception.NetworkNotFound(network_id=network_info['id'])
        network['label'] = network['name']

        if isinstance(network, types.StringType):
            ret = json.loads(network)
        return network

    def get_port_from_neutron_by_id(self, context, port_id):
        """
        get port info from neutron by port id
        :param context:
        :param port_id:
        :return:
        """
        return self._neutron.show_port(context, port_id)

    def get_subnet_from_neutron_by_id(self, context, subnet_id):
        """
        get subnet info from neutron by neutron id
        :param context:
        :param subnet_id:
        :return:
        """
        return self.get_subnet_by_id(context, subnet_id)
    def get_subnet_by_id(self, context,subnet_id):
        search_pots = {'id': subnet_id}
        data = neutron_api.get_client(context).list_subnets(**search_pots)
        ipam_subnets = data.get('subnets', [])
        result = None
        for subnet in ipam_subnets:
            if subnet_id == subnet['id']:
                result = subnet
                break
        return result
	    

    def get_subnet_by_port_id(self, context, port_id):
        """
        get subnet form neutron by port id
        return port item 0 subnet info
        :param context:
        :param port_id:
        :return:
        """
        port_detail = self.get_port_from_neutron_by_id(context, port_id)
        subnet_id = None
        if port_detail and port_detail.get("port"):
            port = port_detail.get("port")
            fixed_ips = port['fixed_ips']
            if fixed_ips:
                subnet_id = fixed_ips[0]['subnet_id']
        if subnet_id:
            return self.get_subnet_from_neutron_by_id(context, subnet_id)
        else:
            return None

    def is_enable_dhcp(self, context, port_id):
        """
        check if subnet is enable dhcp
        :param context:
        :param port_id:
        :return:
        """
        subnet = self.get_subnet_by_port_id(context, port_id)
        if subnet:
            return subnet['enable_dhcp']
        else:
            return False

    def ensure_network(self, network_info, checksum_enable=False, extra_specs=None):
        """
            Ensure network resource on FC

        :param network_info: network_info from nova, dictionary type
        :return:
        """
        # NOTE: physical network only visible to admin user

        context = nova_ctxt.get_admin_context()

        network = self._get_network_from_neutron(context, network_info)
        LOG.info(_('get network info from neutron: %s'), network)
        network_info['checksum_enable'] = checksum_enable
        dvs_id = self.get_dvs_id(extra_specs, network)
        if not dvs_id:
            raise fc_exc.DVSwitchNotFound(
                dvs_id=network['provider:physical_network'])

        if checksum_enable is True:
            pg_adpt = PortGroupSuffixQueryAdapter(network, dvs_id, 'checksum')
        else:
            pg_adpt = PortGroupQueryAdapter(network, dvs_id)

        pg_data = self.query_port_group(pg_adpt)
        if not pg_data:
            try:
                if checksum_enable is True:
                    pg_adpt = PortGroupSuffixCreateAdapter(network, dvs_id, 'checksum')
                else:
                    pg_adpt = PortGroupCreateAdapter(network, dvs_id)

                pg_data = self.create_port_group(dvs_id, pg_adpt)
            except Exception as e:
                # race condition
                LOG.warn(_('create pg failed (%s), will check it again'), e)
                pg_adpt = PortGroupQueryAdapter(network, dvs_id)
                pg_data = self.query_port_group(pg_adpt)

        return pg_data['urn'] if pg_data else None

    def get_dvs_id(self, extra_specs, network):

        dvs_name = None
        physnet_name = None
        if network.get('segments'):
            for segment in network['segments']:
                if segment['provider:network_type'] == constant.TYPE_VLAN:
                    LOG.info(_('get dvs id which network is vlan with segments'))
                    physnet_name = segment['provider:physical_network']
                    network.update(segment)
                    break
        else:
            if network['provider:network_type'] == constant.TYPE_VXLAN:
                if not constant.CONF.fusioncompute.vxlan_dvs_name \
                        and not self.is_instance_use_enhanced_network(extra_specs):
                    raise fc_exc.DVSwitchNotFound(dvs_id='vxlan dvs name')
                dvs_name = constant.CONF.fusioncompute.vxlan_dvs_name
            else:
                LOG.info(_('get dvs id which network is vlan without segments'))
                physnet_name = network['provider:physical_network']

        if self.is_instance_use_enhanced_network(extra_specs):
            if not constant.CONF.fusioncompute.enhanced_network_dvs_name:
                raise fc_exc.DVSwitchNotFound(dvs_id='enhanced network dvs name')
            dvs_name = constant.CONF.fusioncompute.enhanced_network_dvs_name

        if dvs_name:
            dvs_id = self._get_dvs_id_by_dvs_name(dvs_name)
        else:
            dvs_id = self._get_dvs_id_by_physnet_name(physnet_name)

        return dvs_id

    def is_instance_use_enhanced_network(self, instance_extra_specs):
        if instance_extra_specs:
            instance_vnic_type = instance_extra_specs.get('instance_vnic:type')
            if instance_vnic_type and instance_vnic_type.lower() == 'enhanced':
                return True
        return False

    def create_port_group(self, dvs_id, pg_adpt):
        """
        send message to fusion compute to create a port group

        :param dvs_id:
        :param pg_adpt:
        :return:
        """
        ret = self.post(self.get_path_by_site(constant.PORT_GROUP_URI,
                                              dvs_id=dvs_id),
                        data=pg_adpt.to_json())
        return ret

    def query_port_group(self, pg_adapter):
        """

        :param pg_adapter:
        :return:
        """
        query_path = self.get_path_by_site('/portgroups')

        ret = self.post(query_path,
                        data=jsonutils.dumps({'names': pg_adapter.names}))

        return ret['portGroups'][0] if ret and ret.get('portGroups') else None

    def create_vsp(self, dvs_id, pg_urn, vif):
        """
        send message to fusion compute to create a vsp

        :param dvs_id:
        :param pg_urn:
        :param vif:
        :return:
        """
        vsp_path = self.get_path_by_site(constant.VSP_URI,
                                         dvs_id=dvs_id)
        port_id = vif['id']

        body = {
            'name': port_id,
            'portGroupUrn': pg_urn,
            'tags': [{'tagKey': constant.VSP_TAG_KEY, 'tagValue': port_id}]
        }

        ret = self.post(vsp_path, data=jsonutils.dumps(body))

        return ret

    def delete_vsps(self, vifs):
        """
        send message to fusion compute to delete vsp

        :param vifs:
        :return:
        """
        vsps = [self.query_vsp(vif) for vif in vifs]

        for vsp in vsps:
            self.delete(vsp['uri'])

    def query_vsp(self, vif):
        """
        send message to fusion compute to query vsp information

        :param vif:
        :return:
        """
        ret = self.post(self.get_path_by_site('/vsps?limit=0&offset=1'),
                        data=jsonutils.dumps([
                            {
                                'tagKey': constant.VSP_TAG_KEY,
                                'tagValue': vif['id'],
                            }
                        ]))
        if not ret or not ret.get('vsps'):
            raise fc_exc.VSPNotFound(vsp_id=vif['id'])
        return ret['vsps'][0]

    def del_port_group(self, dvs_id, pg_id):
        """
        send message to fusion compute to create a port group

        :param dvs_id:
        :param pg_adpt:
        :return:
        """
        url = self.get_path_by_site(constant.PORT_GROUP_ID_URI,
                                    dvs_id = dvs_id,
                                    pg_id = pg_id)
        self.delete(url)

    def _get_pg_id_pg_date(self, pg_data):
        urn = pg_data.get('urn')
        if urn is None:
            return None

        pg_data_list = re.split(':', urn)
        if len(pg_data_list)<7:
            return None

        pg_id = pg_data_list[6]
        return pg_id

    def query_all_pg(self):
        query_path = self.get_path_by_site('/portgroups')
        offset = 0
        pg_list = []
        while True:
            ret = self.post(query_path,
                            data=jsonutils.dumps({'limit': 100,
                                                  'offset': offset}))
            temp_list = ret.get('portGroups')
            if isinstance(temp_list, list):
                pg_list.extend(temp_list)
            else:
                break

            if len(temp_list) < 100:
                break
            else:
                offset = len(pg_list)
            time.sleep(0.005)
        return pg_list

    def audit_pg(self):
        context = nova_ctxt.get_admin_context()
        networks = self._neutron.get_all(context=context)
        self._init_all_fc_dvs()

        pg_list = self.query_all_pg()
        for pg in pg_list:
            pg_name_ayn_list = []
            try:
                pg_name_ayn_list = re.split('#', pg['name'])
            except:
                pass
            if len(pg_name_ayn_list) < 3:
                continue

            fc_network_name = pg_name_ayn_list[0]
            fc_network_id = pg_name_ayn_list[1]
            fc_dvs_id = pg_name_ayn_list[2]
            pg_id = self._get_pg_id_pg_date(pg)
            
            if fc_network_name is None \
                    or fc_network_id is None\
                    or fc_dvs_id is None\
                    or pg_id is None:
                continue

            if fc_dvs_id not in self.dvs_mapping.values():
                continue
            pg_user = pg.get('userName')
            if pg_user is None:
                continue
            if pg_user != constant.CONF.fusioncompute.fc_user:
                continue

            is_need_remove = True
            for network in networks:
                if network['name'] == fc_network_name \
                        and network['id'] == fc_network_id:
                    is_need_remove = False
                    break
            
            if is_need_remove:
                try:
                    self.del_port_group(fc_dvs_id, pg_id)
                    LOG.warn('port group remove dvs_id=%s,ps_id=%s',fc_dvs_id,pg_id)
                except Exception:
                    LOG.error('Error happen while delete port group remove '
                              'dvs_id=%s,ps_id=%s', fc_dvs_id, pg_id)
                    pass
