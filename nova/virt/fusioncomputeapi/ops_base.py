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


class OpsBase(object):
    """OpsBase

    fc operation base class
    """

    def set_client(self, fc_client):
        """set_client

        set client obj
        :param fc_client:
        :return:
        """
        self.fc_client = fc_client
        if self.fc_client:
            self.site = self.fc_client.context
        else:
            self.site = None

    def __init__(self, fc_client):
        self.fc_client = None
        self.site = None
        self.set_client(fc_client)

    @property
    def site_id(self):
        """site_id

        get site id
        :return:
        """
        return self.site['site_id']

    def get_path_by_site(self, path=None, **kwargs):
        """get_path_by_site

        get rest path by site
        :param path:
        :param kwargs:
        :return:
        """
        return self.site.get_path_by_site(path, **kwargs)

    def post(self, path, data=None, **kwargs):
        """post

            Post.
        :param path: path under Context, something like '/app/resource'
        :param data: (Optional) data of request
        :param kwargs: headers, etc.
        :return: Response object in requests
        """
        return self.fc_client.post(path, data=data, **kwargs)

    def get(self, path, **kwargs):
        """get

            Get.
        :param path: path under Context, something like '/app/resource/id'
        :param kwargs:  headers, etc.
        :return: Response object in requests
        """
        return self.fc_client.get(path, **kwargs)

    def put(self, path, data=None, **kwargs):
        """put

            Put.
        :param path: path under Context, something like '/app/resource/id'
        :param data: (Optional) data of request
        :param kwargs: headers, etc.
        :return: Response object in requests
        """
        return self.fc_client.put(path, data=data, **kwargs)

    def delete(self, path, **kwargs):
        """delete

            Delete.
        :param path: path under Context, something like '/app/resource/id'
        :param kwargs: headers, etc.
        :return: Response object in requests
        """
        return self.fc_client.delete(path, **kwargs)
