"""
    FC operation with task obj
"""

from nova.virt.fusioncomputeapi import ops_base
from nova.virt.fusioncomputeapi import taskops

class OpsTaskBase(ops_base.OpsBase):
    """
    fc operation with task obj
    """
    def __init__(self, fc_client, task_ops):
        super(OpsTaskBase, self).__init__(fc_client)
        self.task_ops = task_ops

    def post(self, path, data=None, excp=None, fixedInterval=0, **kwargs):
        """
            Post.
        :param path: path under Context, something like '/app/resource'
        :param data: (Optional) data of request
        :param kwargs: headers, etc.
        :return: Response object in requests
        """
        @taskops.wait_task_done(self.task_ops, excp, fixedInterval)
        def _post():
            """
            inner post func
            """
            #ignore pylint:disable=W0142
            return super(OpsTaskBase, self).post(path, data, **kwargs)
        return _post()

    def put(self, path, data=None, excp=None, fixedInterval=0, **kwargs):
        """
            Put.
        :param path: path under Context, something like '/app/resource/id'
        :param data: (Optional) data of request
        :param kwargs: headers, etc.
        :return: Response object in requests
        """
        @taskops.wait_task_done(self.task_ops, excp, fixedInterval)
        def _put():
            """
            inner put func
            """
            #ignore pylint:disable=W0142
            return super(OpsTaskBase, self).put(path, data, **kwargs)
        return _put()

    def delete(self, path, excp=None, **kwargs):
        """
            Delete.
        :param path: path under Context, something like '/app/resource/id'
        :param kwargs: headers, etc.
        :return: Response object in requests
        """
        @taskops.wait_task_done(self.task_ops, excp)
        def _delete():
            """
            inner delete func
            :return:
            """
            #ignore pylint:disable=W0142
            return super(OpsTaskBase, self).delete(path, **kwargs)
        return _delete()
