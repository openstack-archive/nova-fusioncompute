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
import math

from nova.i18n import _
from nova.virt.fusioncomputeapi import constant
from nova.virt.fusioncomputeapi import exception as fc_exc
from nova.virt.fusioncomputeapi.fcinstance import FC_INSTANCE_MANAGER as FC_MGR
from nova.virt.fusioncomputeapi import ops_task_base
from nova.virt.fusioncomputeapi import utils
from nova.virt.fusioncomputeapi.utils import LOG
from oslo_serialization import jsonutils

UTC_TIME_TO_SEC = 1000


class ClusterOps(ops_task_base.OpsTaskBase):
    """cluster system manager and driver resouce info

    """

    def __init__(self, fc_client, task_ops):
        super(ClusterOps, self).__init__(fc_client, task_ops)
        self._stats = {}
        self.clusters = {}
        self.resources = []

    def list_all_clusters(self):
        """get all cluster info

        :return:
        """
        LOG.info('list_all_clusters self.site.cluster_uri:%s .' %
                 self.site.cluster_uri)

        cluster_list = self.get(self.site.cluster_uri)['clusters']
        LOG.debug('clusters:%s' % cluster_list)
        return cluster_list

    def init_all_cluster(self):
        """get all cluster info

        :return:
        """
        LOG.debug('self.site.cluster_uri:%s .' % self.site.cluster_uri)

        cfg_cluster_list = utils.split_strip(
            constant.CONF.fusioncompute.clusters)
        cluster_list = self.get(self.site.cluster_uri)['clusters']
        LOG.debug(
            'clusters:%s, split:%s .' %
            (constant.CONF.fusioncompute.clusters,
             ','.join(cfg_cluster_list)))

        self.clusters = {}
        for cluster in cluster_list:
            if cluster['name'] in cfg_cluster_list:
                self.clusters[cluster['name']] = cluster

    def get_cluster_detail_by_nodename(self, nodename):
        """get cluster by node name"""
        cluster_urn = self.get_cluster_urn_by_nodename(nodename)
        return self.get(utils.generate_uri_from_urn(cluster_urn))

    def get_local_cluster_urn_list(self):
        """get local config cluster urn

        :return:
        """
        self.init_all_cluster()
        return [cluster['urn'] for cluster in self.clusters.values()]

    def get_cluster_urn_by_nodename(self, nodename):
        """get cluster urn by node name"""
        cluster_name = self.get_cluster_name_by_nodename(nodename)
        if cluster_name:
            self.init_all_cluster()
            if self.clusters.get(cluster_name):
                return self.clusters.get(cluster_name)['urn']
        return None

    def get_cluster_urn_for_migrate(self, nodename):
        """get cluster urn by node name"""
        cluster_name = self.get_cluster_name_by_nodename(nodename)
        if cluster_name:
            clusters = self.get(self.site.cluster_uri)['clusters']
            for cluster in clusters:
                if cluster_name == cluster['name']:
                    return cluster['urn']
        return None

    def update_resources(self):
        """ini hypervisor info list

        :return:
        """
        self.resources = []
        self.init_all_cluster()
        for cluster_name in self.clusters:
            self.resources.append(self.create_nodename(cluster_name))

    def get_cluster_name_by_nodename(self, nodename):
        """get cluster name by node info"""
        if nodename:
            temps = nodename.split('@')
            if len(temps) != 2:
                return nodename
            else:
                return temps[1]
        else:
            return nodename

    def get_available_resource(self, nodename):
        """Retrieve resource info.

        This method is called when nova-compute launches, and
        as part of a periodic task.

        :returns: dictionary describing resources
        """
        LOG.debug(_("get_available_resource,"
                    " nodename: %s ." % nodename))
        cluster_name = self.get_cluster_name_by_nodename(nodename)
        cluster_resource = self.get_cluster_resource(cluster_name)
        if not cluster_resource:
            LOG.error(_("Invalid cluster name : %s"), nodename)
            return {}

        cluster_resource['cpu_info'] = \
            jsonutils.dumps(cluster_resource['cpu_info'])
        # cluster_resource['supported_instances'] = jsonutils.dumps(
        #    cluster_resource['supported_instances'])

        LOG.debug("the resource status is %s", cluster_resource)
        return cluster_resource

    def _query_host_by_scope(self, scope):
        """Query host info

        :param scope : clusterUrn , dvswitchUrn or datasotroeUrn
        :return a list of host in scope
        """
        host_uri = utils.build_uri_with_params(self.site.host_uri,
                                               {'scope': scope})
        return self.get(host_uri)['hosts']

    def _get_cluster_computeresource(self, cluster):
        computeres_uri = cluster["uri"] + "/" + \
            "allvmcomputeresource?isNeedAllocVcpus=true&detail=true"
        return self.get(computeres_uri)

    def get_resource_group(self, cluster_urn, instance_group):

        resource_group_uri = utils.generate_uri_from_urn(
            cluster_urn) + '/resourcegroups'
        condition = {'type': 0, 'useType': 1, 'name': instance_group[
            'uuid'], 'limit': 100, 'offset': 0}
        resource_group_uri = utils.build_uri_with_params(
            resource_group_uri, condition)
        resource_groups = self.get(resource_group_uri).get('groups')
        if resource_groups:
            return resource_groups[0]
        else:
            return None

    def get_resource_group_list(self, cluster_urn):

        resource_group_uri = utils.generate_uri_from_urn(
            cluster_urn) + '/resourcegroups'

        offset = 0
        limit = 100
        resourcegroups_all = []
        while True:
            condition = {
                'limit': limit,
                'offset': offset,
                'type': 0,
                'useType': 1
            }
            resource_group_uri = utils.build_uri_with_params(
                resource_group_uri, condition)
            response = self.get(resource_group_uri)

            total = int(response.get('total') or 0)
            if total > 0:
                resourcegroups = response.get('groups')
                resourcegroups_all += resourcegroups
                offset += len(resourcegroups)
                if offset >= total or len(resourcegroups_all) >= total or len(
                        resourcegroups) < limit:
                    break
            else:
                break
        return resourcegroups_all

    def delete_resource_group(self, resource_group_urn):

        resource_group_uri = utils.generate_uri_from_urn(resource_group_urn)

        self.delete(resource_group_uri)

    def create_resource_group(self, cluster_urn, instance_group):

        resource_group_uri = utils.generate_uri_from_urn(
            cluster_urn) + '/resourcegroups'
        body = {'type': 0, 'useType': 1, 'name': instance_group[
            'uuid'], 'policies': instance_group.get('policies')}

        resource_group = self.post(resource_group_uri, data=body)

        return resource_group['urn']

    def get_fc_current_time(self):
        current_time = self.get(self.site.current_time_uri)
        if current_time:
            utc_time = current_time["currentUtcTime"]
            utc_time_num_value = int(utc_time) / UTC_TIME_TO_SEC
            return utc_time_num_value
        return None

    def get_cpu_usage(self, monitor_period, cluster_urn):
        end_time = self.get_fc_current_time()
        start_time = end_time - (monitor_period * 2)

        body = [
            {
                "startTime": str(start_time),
                "endTime": str(end_time),
                "interval": str(monitor_period),
                "metricId": "cpu_usage",
                "urn": cluster_urn
            }
        ]

        LOG.debug("get_cpu_usage body:%s", json.dumps(body))
        response = self.fc_client.post(self.site.metric_curvedata_uri,
                                       data=body)
        LOG.debug("get_cpu_usage body:%s response:%s",
                  json.dumps(body), json.dumps(response))
        if response:
            if len(response["items"]) > 0:
                metric_value = response["items"][0]["metricValue"]
                if len(metric_value) > 0:
                    value = metric_value[0]["value"]
                    if len(metric_value) is 2:
                        if metric_value[1]["value"] is not None:
                            value = metric_value[1]["value"]
                    return value
        return None

    def get_cluster_stats_by_name(self, cluster_name):
        """Get the aggregate resource stats of a cluster."""
        cpu_info = dict(vcpus=0, cores=0, pcpus=0, vendor=[], model=[])
        mem_info = dict(total=0, used=0)
        cluster_urn = None
        cluster_query_info = {'name': cluster_name}
        cluster_query_uri = utils.build_uri_with_params(self.site.cluster_uri,
                                                        cluster_query_info)
        clusters = self.get(cluster_query_uri)['clusters']
        find_cluster = None
        if clusters:
            for cluster in clusters:
                if cluster['name'] == cluster_name:
                    find_cluster = cluster

        if find_cluster:
            cluster_urn = find_cluster['urn']
            hosts = self._query_host_by_scope(cluster_urn)
            for host in hosts:
                if host['status'] == 'normal' and (not host['isMaintaining']):
                    if 'vendor' in host:
                        cpu_info['vendor'].append(host['vendor'])
                    if 'model' in host:
                        cpu_info['model'].append(host['model'])
                    if 'physicalCpuQuantity' in host:
                        cpu_info['pcpus'] += host['physicalCpuQuantity']

            computeresource = self._get_cluster_computeresource(find_cluster)
            cpuResource = computeresource["cpuResource"]
            memResource = computeresource["memResource"]

            allocated_cpu_detail = computeresource.get('detailCpuResource')
            allocated_mem_detail = computeresource.get('detailMemResource')

            cpu_info["vcpus"] = cpuResource.get("totalVcpus", 0)
            cpu_info["allocatedVcpus"] = cpuResource.get("allocatedVcpus", 0)
            cpu_info["totalSizeMHz"] = cpuResource.get("totalSizeMHz")
            cpu_info["allocatedSizeMHz"] = cpuResource.get("allocatedSizeMHz")
            cpu_info["stopVmAllocatedVcpus"] = 0
            if allocated_cpu_detail is not None:
                cpu_info["stopVmAllocatedVcpus"] = allocated_cpu_detail.get(
                    'allocatedVcpus').get("Stopped")

            mem_info['total'] = memResource.get("totalSizeMB", 0)
            mem_info['used'] = memResource.get("allocatedSizeMB", 0)
            mem_info["stopVmAllocatedMem"] = 0
            if allocated_mem_detail is not None:
                mem_info["stopVmAllocatedMem"] = allocated_mem_detail.get(
                    'allocatedSizeMB').get("Stopped")

            cpu_usage_monitor_period = \
                constant.CONF.fusioncompute.cpu_usage_monitor_period
            if cpu_usage_monitor_period not in [300, 1800, 3600, 86400]:
                cpu_usage_monitor_period = 3600
            cpu_info["usage"] = self.get_cpu_usage(cpu_usage_monitor_period,
                                                   cluster_urn)

            data = {'cpu': cpu_info, 'mem': mem_info}
            return cluster_urn, data
        else:
            LOG.warn(_("get cluster status failed, use default."))
            data = {'cpu': cpu_info, 'mem': mem_info}
            return cluster_urn, data

    def query_datastore_by_cluster_urn(self, cluster_urn):
        """Query """
        datastore_cond = {'status': 'NORMAL', 'scope': cluster_urn}
        datastore_uri = utils.build_uri_with_params(self.site.datastore_uri,
                                                    datastore_cond)
        return self.get(datastore_uri)['datastores']

    def get_hypervisor_type(self):
        """Returns the type of the hypervisor."""
        return constant.FC_DRIVER_JOINT_CFG['hypervisor_type']

    def get_hypervisor_version(self):
        """Get hypervisor version."""
        return constant.FC_DRIVER_JOINT_CFG['hypervisor_version']

    def create_nodename(self, cluster_name):
        """Creates the name that is stored in hypervisor_hostname column.

        The name will be of the form similar to
        site001_GlodCluster008
        """
        return '@'.join([self.site_id, cluster_name])

    def get_instance_capabilities(self):
        """get_instance_capabilities"""
        return [('i686', 'xen', 'xen'),
                ('x86_64', 'xen', 'xen')]

    def get_running_vms(self, cluster_urn):
        """return vm counts in this cluster

        :param cluster_urn:
        :return:
        """
        return FC_MGR.get_total_vm_numbers(scope=cluster_urn,
                                           isTemplate=False,
                                           group=constant.VM_GROUP_FLAG)

    def get_cluster_resource(self, cluster_name):
        """get the current state of the cluster."""
        res = {}
        cluster_urn, cluster_stats = \
            self.get_cluster_stats_by_name(cluster_name)

        disk_total = 0
        disk_available = 0

        datastores = self.query_datastore_by_cluster_urn(cluster_urn)
        for datastore in datastores:
            disk_total += datastore['actualCapacityGB']
            disk_available += datastore['actualFreeSizeGB']

        res["vcpus"] = int(int(cluster_stats['cpu']['vcpus'])
                           * constant.CONF.fusioncompute.cpu_ratio)
        res["memory_mb"] = cluster_stats['mem']['total']
        res["local_gb"] = disk_total
        res["numa_topology"] = None
        res['vcpus_used'] = self._calculate_vcpu_mem_used(
            cluster_stats["cpu"]['stopVmAllocatedVcpus'],
            cluster_stats["cpu"]["allocatedVcpus"])
        res['memory_mb_used'] = self._calculate_vcpu_mem_used(
            cluster_stats["mem"]['stopVmAllocatedMem'],
            cluster_stats['mem']['used'])
        res['local_gb_used'] = disk_total - disk_available
        cpu_info = cluster_stats["cpu"]
        topology = {"cores": cpu_info['cores'],
                    "threads": cpu_info['vcpus']}
        extra_cpu_info = {
            "totalSizeMHz": str(cpu_info["totalSizeMHz"]),
            "allocatedSizeMHz": str(cpu_info["allocatedSizeMHz"]),
            "usage": str(cpu_info["usage"])
        }

        res["cpu_info"] = {"vendor": cpu_info['vendor'],
                           "model": cpu_info['model'],
                           "topology": topology,
                           "extra_info": extra_cpu_info,
                           'pcpus': cpu_info['pcpus']}
        res["hypervisor_type"] = self.get_hypervisor_type()
        res["hypervisor_version"] = self.get_hypervisor_version()
        res["hypervisor_hostname"] = self.create_nodename(cluster_name)
        res["supported_instances"] = self.get_instance_capabilities()

        res['running_vms'] = self.get_running_vms(cluster_urn)

        return res

    def _calculate_vcpu_mem_used(self, stopped_vm_allocated, all_vm_allocated):
        resource_reduced_rate = 100
        if constant.CONF.fusioncompute.resource_reduced_rate is not None:
            resource_reduced_rate\
                = constant.CONF.fusioncompute.resource_reduced_rate
        return all_vm_allocated - stopped_vm_allocated \
            + math.ceil(stopped_vm_allocated *
                        float(resource_reduced_rate) / 100)

    def _modify_cluster(self, cluster, changes):
        """_modify_cluster

        :param cluster: fc cluster
        :param changes: modify body {}
        :return:
        """

        self.put(cluster['uri'],
                 data=changes,
                 excp=fc_exc.ModifyClusterFailure)

    def _get_drs_rules_from_cluster(self, cluster, rule_name, rule_type):
        """_get_drs_rules_from_cluster

        :param cluster:
        :param rule_name:
        :param rule_type:
        :return:
        """
        drs_rules = cluster['drsSetting']['drsRules']
        for drs_rule in drs_rules:
            if drs_rule['ruleName'] == rule_name \
                    and drs_rule['ruleType'] == rule_type:
                return drs_rule
        return None

    def create_drs_rules(self, cluster, rule_name, rule_type):
        """create_drs_rules

        :param cluster:
        :param rule_name:
        :param rule_type:
        :return:
        """

        rule = self._get_drs_rules_from_cluster(cluster, rule_name, rule_type)
        if rule:
            LOG.debug(_("drs rules %s already exists"), rule_name)
            return

        body = {
            'drsSetting': {
                'drsRules': [{
                    'operationType': constant.DRS_RULES_OP_TYPE_MAP['create'],
                    'ruleName': rule_name,
                    'ruleType': rule_type
                }]
            }
        }
        self._modify_cluster(cluster, body)
        LOG.debug(_("create drs rules %s succeed"), rule_name)

    def delete_drs_rules(self, cluster, rule_name, rule_type):
        """delete_drs_rules

        :param cluster:
        :param rule_name:
        :param rule_type:
        :return:
        """

        rule = self._get_drs_rules_from_cluster(cluster, rule_name, rule_type)
        if rule is None:
            LOG.debug(_("drs rules %s not exists"), rule_name)
            return

        body = {
            'drsSetting': {
                'drsRules': [{
                    'operationType': constant.DRS_RULES_OP_TYPE_MAP['delete'],
                    'ruleIndex': rule['ruleIndex']
                }]
            }
        }
        self._modify_cluster(cluster, body)
        LOG.debug(_("delete drs rules %s succeed"), rule_name)

    def modify_drs_rules(self, cluster, rule_name, rule_type, vms):
        """modify_drs_rules

        :param cluster:
        :param rule_name:
        :param rule_type:
        :param vms:
        :return:
        """

        rule = self._get_drs_rules_from_cluster(cluster, rule_name, rule_type)
        if rule is None:
            msg = _("Can not find drs rules: name=%s,"
                    " type=%d") % (rule_name, rule_type)
            raise fc_exc.AffinityGroupException(reason=msg)

        body = {
            'drsSetting': {
                'drsRules': [{
                    'operationType': constant.DRS_RULES_OP_TYPE_MAP['modify'],
                    'ruleIndex': rule['ruleIndex'],
                    'ruleName': rule_name,
                    'ruleType': rule_type,
                    'vms': vms
                }]
            }
        }
        self._modify_cluster(cluster, body)
        LOG.debug(_("modify drs rules %s succeed"), rule_name)
