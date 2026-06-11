from ferret.server.registry    import TokenRegistry
from ferret.server.acl         import Acl
from ferret.server.tun_gateway import TunGateway
from ferret.server.token_gen   import TokenGen
from ferret.server.ca          import CertAuthority
from ferret.server.audit       import AuditLog

__all__ = ["AgentRouter", "TokenRegistry", "Acl", "TunGateway", "TokenGen",
           "CertAuthority", "AuditLog"]


def __getattr__(name):
    if name == "AgentRouter":
        from ferret.server.router import AgentRouter
        return AgentRouter
    raise AttributeError(name)
