# Infoblox vNIOS Deployment on OpenStack

## Overview

Deploy Infoblox vNIOS virtual DDI (DNS/DHCP/IPAM) appliance on OpenStack for use with the Skyline DNS & IPAM panel. vNIOS provides WAPI (Web API) for programmatic DNS/DHCP/IPAM management.

## Requirements

- **Image**: nios-9.0.3-50212 qcow2 (or newer), ~3.8GB, 500GB virtual disk
- **Flavor**: Minimum 8 vCPU, 16GB RAM (e.g., m3-xlarge)
- **Networks**: Two separate networks required (MGMT + LAN1)
- **Volume**: Boot from volume (500GB), must be fresh from Glance image

## NIC Order (Critical)

vNIOS maps NICs by order:

| NIC Order | vNIOS Interface | Purpose |
|-----------|----------------|---------|
| 1st `--port` | MGMT (eth0) | Out-of-band management (not used for WAPI on vNIOS) |
| 2nd `--port` | LAN1 (eth1) | Primary data/DNS/WAPI interface |
| 3rd `--port` | HA (eth2) | High Availability (optional) |
| 4th `--port` | LAN2 (eth3) | Secondary data (optional) |

**Important**: `set network` CLI command configures the **LAN1** interface (2nd NIC), NOT the MGMT interface. WAPI and Grid Manager run on LAN1. The MGMT port cannot be enabled on vNIOS (`set lom` and `set interface` are not supported on virtual appliances).

### Correct Port Order for OpenStack

Since WAPI runs on LAN1 (2nd NIC), place your management/routable network as the **second port**:

```bash
openstack server create NIOS \
  --volume <boot-volume> \
  --flavor m3-xlarge \
  --port <dummy-mgmt-port>  \   # 1st = MGMT (eth0) - can be on any network
  --port <wapi-access-port>     # 2nd = LAN1 (eth1) - WAPI accessible here
```

## Deployment Steps

### 1. Upload Image to Glance

```bash
openstack image create NIOS-9.0.3 \
  --file nios-9.0.3-50212-fixed-500G.qcow2 \
  --disk-format qcow2 --container-format bare \
  --property hw_disk_bus=virtio
```

### 2. Create Networks

```bash
# Network for WAPI access (will be LAN1)
openstack network create nios-setup-net --share
openstack subnet create nios-setup-subnet \
  --network nios-setup-net \
  --subnet-range 192.168.1.0/24 \
  --gateway 192.168.1.1

# Dummy network for MGMT NIC (required for 2-NIC boot)
openstack network create nios-lan1 --share
openstack subnet create nios-lan1-subnet \
  --network nios-lan1 \
  --subnet-range 10.10.10.0/24 \
  --gateway 10.10.10.1 --no-dhcp
```

### 3. Create Router for External Connectivity

```bash
openstack router create nios-router
openstack router set nios-router --external-gateway PUBLIC-ILL
openstack router add subnet nios-router nios-setup-subnet
```

### 4. Create Ports

```bash
# Dummy MGMT port (1st NIC)
openstack port create nios-mgmt-port \
  --network nios-lan1 \
  --fixed-ip ip-address=10.10.10.2 \
  --security-group Allow-Everything

# WAPI access port (2nd NIC = LAN1)
openstack port create nios-lan1-port \
  --network nios-setup-net \
  --fixed-ip ip-address=192.168.1.2 \
  --security-group Allow-Everything
```

### 5. Create Boot Volume

Always create a fresh volume from the Glance image. Never reuse volumes from failed boots.

```bash
openstack volume create NIOS-boot \
  --image NIOS-9.0.3 --size 500 --bootable
```

### 6. Launch Instance

```bash
openstack server create NIOS \
  --volume NIOS-boot \
  --flavor m3-xlarge \
  --port nios-mgmt-port \
  --port nios-lan1-port
```

### 7. Assign Floating IP (Optional)

```bash
openstack floating ip create PUBLIC-ILL
openstack server add floating ip NIOS <floating-ip>
```

## Post-Deployment Configuration

### First Boot

vNIOS performs Manufacturing Initialization on first boot (~3-5 minutes). Monitor via VNC console:

1. NIOS boot init
2. DHCP attempts (may fail if no DHCP on subnet)
3. Infoblox system initializing
4. Starting services
5. Login prompt appears

### Configure Network (if DHCP not available)

Via VNC console:

```
login: admin
password: infoblox

Infoblox > set network
  Enter IP address: 192.168.1.2
  Enter netmask [255.255.255.0]: 255.255.255.0
  Enter gateway address [192.168.1.1]: 192.168.1.1
```

### Verify WAPI

```bash
curl -sk -u admin:infoblox https://192.168.1.2/wapi/v2.12/grid
```

Expected response:
```json
[{"_ref": "grid/...","name": "Infoblox"}]
```

## Skyline Integration

After WAPI is accessible, add the connection via the Skyline DNS & IPAM panel:

1. Navigate to **Network > DNS & IPAM** (admin only)
2. Click **Add Connection**
3. Select provider: **Infoblox DDI**
4. Enter WAPI URL: `https://192.168.1.2/wapi/v2.12`
5. Enter credentials: admin / infoblox
6. Click **Test Connection**
7. If successful, click **Save**

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| "Fatal error during Infoblox startup" | Single NIC (missing LAN1) | Must have 2+ NICs |
| WAPI timeout, ARP resolves | IP on wrong NIC (MGMT vs LAN1) | Swap NIC order in `server create` |
| "Connection refused" on 443 | WAPI service still starting | Wait 3-5 minutes after boot |
| "No route to host" | NIOS firewall or port security | Add Allow-Everything security group |
| DHCP failure during boot | Subnet has --no-dhcp | Expected; configure via `set network` |
| Manufacturing Init doesn't run | Reused volume from failed boot | Create fresh volume from Glance image |

## Lessons Learned

1. **NIC order matters**: MGMT=1st, LAN1=2nd. `set network` configures LAN1 only.
2. **vNIOS has no MGMT port**: `set lom` and `set interface mgmt` are not supported on vNIOS.
3. **Fresh volumes only**: NIOS stores state in the volume. Failed boots corrupt internal state.
4. **Port security**: Enable port security with Allow-Everything SG (not disabled port security).
5. **Boot time**: vNIOS takes 3-5 minutes to fully start services after boot.
