"""
    Base API Class
"""

class OpsBase(object):
    """
    fc operation base class
    """

    def set_client(self, fc_client):
        """
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
        """
        get site id
        :return:
        """
        return self.site['site_id']

    def get_path_by_site(self, path=None, **kwargs):
        """
        get rest path by site
        :param path:
        :param kwargs:
        :return:
        """
        return self.site.get_path_by_site(path, **kwargs)

    def post(self, path, data=None, **kwargs):
        """
            Post.
        :param path: path under Context, something like '/app/resource'
        :param data: (Optional) data of request
        :param kwargs: headers, etc.
        :return: Response object in requests
        """
        return self.fc_client.post(path, data=data, **kwargs)

    def get(self, path, **kwargs):
        """
            Get.
        :param path: path under Context, something like '/app/resource/id'
        :param kwargs:  headers, etc.
        :return: Response object in requests
        """
        return self.fc_client.get(path, **kwargs)

    def put(self, path, data=None, **kwargs):
        """
            Put.
        :param path: path under Context, something like '/app/resource/id'
        :param data: (Optional) data of request
        :param kwargs: headers, etc.
        :return: Response object in requests
        """
        return self.fc_client.put(path, data=data, **kwargs)

    def delete(self, path, **kwargs):
        """
            Delete.
        :param path: path under Context, something like '/app/resource/id'
        :param kwargs: headers, etc.
        :return: Response object in requests
        """
        return self.fc_client.delete(path, **kwargs)
