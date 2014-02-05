KILL = 0  # const for killed requests


class ConnectionTypeChange(Exception):
    """
    Gets raised if the connetion type has been changed (e.g. after HTTP/1.1 101 Switching Protocols).
    It's up to the raising ProtocolHandler to specify the new conntype before raising the exception.
    """
    pass


class ProtocolHandler(object):
    def __init__(self, c):
        self.c = c
        """@type : libmproxy.proxy.ConnectionHandler"""

    def handle_messages(self):
        """
        This method gets called if a client connection has been made. Depending on the proxy settings,
        a server connection might already exist as well.
        """
        raise NotImplementedError

    def handle_error(self, error):
        """
        This method gets called should there be an uncaught exception during the connection.
        This might happen outside of handle_messages, e.g. if the initial SSL handshake fails in transparent mode.
        """
        raise error


class TemporaryServerChangeMixin(object):
    """
    This mixin allows safe modification of the target server,
    without any need to expose the ConnectionHandler to the Flow.
    """

    def change_server(self, address, ssl):
        self._backup_server = True
        raise NotImplementedError("You must not change host port port.")

    def restore_server(self):
        if not hasattr(self,"_backup_server"):
            return
        raise NotImplementedError

from . import http, tcp

protocols = {
    'http': dict(handler=http.HTTPHandler, flow=http.HTTPFlow),
    'tcp': dict(handler=tcp.TCPHandler)
}  # PyCharm type hinting behaves bad if this is a dict constructor...


def _handler(conntype, connection_handler):
    if conntype in protocols:
        return protocols[conntype]["handler"](connection_handler)

    raise NotImplementedError


def handle_messages(conntype, connection_handler):
    return _handler(conntype, connection_handler).handle_messages()


def handle_error(conntype, connection_handler, error):
    return _handler(conntype, connection_handler).handle_error(error)