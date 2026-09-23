from app.services.parser_registry import parser_registry
from app.services.vendor_parsers.cisco import parse_cisco
from app.services.vendor_parsers.fortinet import parse_fortinet
from app.services.vendor_parsers.juniper import parse_juniper
from app.services.vendor_parsers.arista import parse_arista
from app.services.vendor_parsers.paloalto import parse_paloalto
from app.services.vendor_parsers.aruba import parse_aruba
from app.services.vendor_parsers.mikrotik import parse_mikrotik
from app.services.vendor_parsers.huawei import parse_huawei
from app.services.vendor_parsers.nokia import parse_nokia
from app.services.vendor_parsers.hpe_comware import parse_hpe_comware
from app.services.vendor_parsers.extreme import parse_extreme
from app.services.vendor_parsers.dell import parse_dell
from app.services.vendor_parsers.checkpoint import parse_checkpoint
from app.services.vendor_parsers.vyos import parse_vyos
from app.services.vendor_parsers.cumulus import parse_cumulus



def register_builtin_parsers():
    parser_registry.register("Cisco", parse_cisco)
    parser_registry.register("Fortinet", parse_fortinet)
    parser_registry.register("Juniper", parse_juniper)
    parser_registry.register("Arista", parse_arista)
    parser_registry.register("Palo Alto Networks", parse_paloalto)
    parser_registry.register("Aruba", parse_aruba)
    parser_registry.register("MikroTik", parse_mikrotik)
    parser_registry.register("Huawei", parse_huawei)
    parser_registry.register("Nokia", parse_nokia)
    parser_registry.register("HPE Comware", parse_hpe_comware)
    parser_registry.register("Extreme Networks", parse_extreme)
    parser_registry.register("Dell Networking", parse_dell)
    parser_registry.register("Check Point", parse_checkpoint)
    parser_registry.register("VyOS", parse_vyos)
    parser_registry.register("NVIDIA Cumulus", parse_cumulus)


register_builtin_parsers()