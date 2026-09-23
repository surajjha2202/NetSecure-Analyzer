from app.services.vendor_detectors import detect_cumulus

config = """nv set system hostname CUMULUS-TEST
nv set interface swp1 ip address 10.0.0.1/24
nv set interface swp1 link state up"""

print(detect_cumulus(config))
