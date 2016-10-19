from nova.console import type

class HuaweiConsoleVNC(type.ConsoleVNC):
    def __innit__(self, host, port, password, internal_access_path=None):
        super(HuaweiConsoleVNC, self).__init__(host, port, internal_access_path)
        self.password = password
