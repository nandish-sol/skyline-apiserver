# Copyright 2021 99cloud
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import annotations

import asyncio
import re
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from starlette.concurrency import run_in_threadpool

from skyline_apiserver import schemas
from skyline_apiserver.api import deps
from skyline_apiserver.client import utils
from skyline_apiserver.client.openstack.keystone import get_token_data
from skyline_apiserver.config import CONF
from skyline_apiserver.db import api as db_api
from skyline_apiserver.log import LOG
from skyline_apiserver.policy import ENFORCER
from skyline_apiserver.schemas.rbac import (
    AllPermissionsData,
    CreateRoleRequest,
    GrantRevokeRequest,
    ImpliedRole,
    ImpliedRolesList,
    PermissionEntry,
    PolicyRule,
    RBACRegistry,
    RoleAssignment,
    RoleAssignmentsList,
    RoleDetail,
    RolePermission,
    RolePermissions,
    RolePermissionsData,
    RolesList,
    RolesPermissionsMatrix,
    ServicePolicies,
    UserDetail,
    UsersList,
)
from skyline_apiserver.utils.roles import assert_system_admin

router = APIRouter()

CURATED_POLICIES: List[ServicePolicies] = [
    ServicePolicies(
        service="nova",
        service_label="Compute",
        categories={
            "Instance Lifecycle": [
                PolicyRule(
                    rule="nova:os_compute_api:servers:index",
                    description="List virtual machines",
                    service="nova",
                    category="Instance Lifecycle",
                    label="List Instances",
                ),
                PolicyRule(
                    rule="nova:os_compute_api:servers:show",
                    description="View virtual machine details",
                    service="nova",
                    category="Instance Lifecycle",
                    label="View Instance Details",
                ),
                PolicyRule(
                    rule="nova:os_compute_api:servers:create",
                    description="Create new virtual machines",
                    service="nova",
                    category="Instance Lifecycle",
                    label="Create Instance",
                ),
                PolicyRule(
                    rule="nova:os_compute_api:servers:delete",
                    description="Delete virtual machines",
                    service="nova",
                    category="Instance Lifecycle",
                    label="Delete Instance",
                ),
                PolicyRule(
                    rule="nova:os_compute_api:servers:update",
                    description="Edit instance name and description",
                    service="nova",
                    category="Instance Lifecycle",
                    label="Edit Instance",
                ),
                PolicyRule(
                    rule="nova:os_compute_api:os-remote-consoles:create",
                    description="Open VNC/SPICE/serial console to an instance",
                    service="nova",
                    category="Instance Lifecycle",
                    label="Access Console",
                ),
            ],
            "Instance Actions": [
                PolicyRule(
                    rule="nova:os_compute_api:servers:start",
                    description="Start a stopped instance",
                    service="nova",
                    category="Instance Actions",
                    label="Start Instance",
                ),
                PolicyRule(
                    rule="nova:os_compute_api:servers:stop",
                    description="Stop a running instance",
                    service="nova",
                    category="Instance Actions",
                    label="Stop Instance",
                ),
                PolicyRule(
                    rule="nova:os_compute_api:servers:reboot",
                    description="Reboot an instance (soft or hard)",
                    service="nova",
                    category="Instance Actions",
                    label="Reboot Instance",
                ),
                PolicyRule(
                    rule="nova:os_compute_api:servers:suspend",
                    description="Suspend an instance to disk",
                    service="nova",
                    category="Instance Actions",
                    label="Suspend Instance",
                ),
                PolicyRule(
                    rule="nova:os_compute_api:servers:resume",
                    description="Resume a suspended instance",
                    service="nova",
                    category="Instance Actions",
                    label="Resume Instance",
                ),
                PolicyRule(
                    rule="nova:os_compute_api:servers:pause",
                    description="Pause an instance in memory",
                    service="nova",
                    category="Instance Actions",
                    label="Pause Instance",
                ),
                PolicyRule(
                    rule="nova:os_compute_api:servers:unpause",
                    description="Unpause a paused instance",
                    service="nova",
                    category="Instance Actions",
                    label="Unpause Instance",
                ),
                PolicyRule(
                    rule="nova:os_compute_api:os-lock-server:lock",
                    description="Lock an instance to prevent accidental changes",
                    service="nova",
                    category="Instance Actions",
                    label="Lock Instance",
                ),
                PolicyRule(
                    rule="nova:os_compute_api:os-lock-server:unlock",
                    description="Unlock a locked instance",
                    service="nova",
                    category="Instance Actions",
                    label="Unlock Instance",
                ),
                PolicyRule(
                    rule="nova:os_compute_api:os-shelve:shelve",
                    description="Shelve an instance (offload from hypervisor)",
                    service="nova",
                    category="Instance Actions",
                    label="Shelve Instance",
                ),
                PolicyRule(
                    rule="nova:os_compute_api:os-shelve:unshelve",
                    description="Unshelve an instance (restore to hypervisor)",
                    service="nova",
                    category="Instance Actions",
                    label="Unshelve Instance",
                ),
                PolicyRule(
                    rule="nova:os_compute_api:servers:rebuild",
                    description="Rebuild instance from a new image",
                    service="nova",
                    category="Instance Actions",
                    label="Rebuild Instance",
                ),
            ],
            "Resize": [
                PolicyRule(
                    rule="nova:os_compute_api:servers:resize",
                    description="Resize instance to a different flavor",
                    service="nova",
                    category="Resize",
                    label="Resize Instance",
                ),
                PolicyRule(
                    rule="nova:os_compute_api:servers:confirm_resize",
                    description="Confirm a pending resize operation",
                    service="nova",
                    category="Resize",
                    label="Confirm Resize",
                ),
                PolicyRule(
                    rule="nova:os_compute_api:servers:revert_resize",
                    description="Revert a pending resize to original flavor",
                    service="nova",
                    category="Resize",
                    label="Revert Resize",
                ),
            ],
            "Attach / Detach": [
                PolicyRule(
                    rule="nova:os_compute_api:os-volumes-attachments:create",
                    description="Attach a volume to an instance",
                    service="nova",
                    category="Attach / Detach",
                    label="Attach Volume",
                ),
                PolicyRule(
                    rule="nova:os_compute_api:os-volumes-attachments:delete",
                    description="Detach a volume from an instance",
                    service="nova",
                    category="Attach / Detach",
                    label="Detach Volume",
                ),
                PolicyRule(
                    rule="nova:os_compute_api:os-attach-interfaces:create",
                    description="Attach a network interface to an instance",
                    service="nova",
                    category="Attach / Detach",
                    label="Attach Interface",
                ),
                PolicyRule(
                    rule="nova:os_compute_api:os-attach-interfaces:delete",
                    description="Detach a network interface from an instance",
                    service="nova",
                    category="Attach / Detach",
                    label="Detach Interface",
                ),
            ],
            "VM Placement": [
                PolicyRule(
                    rule="nova:os_compute_api:os-server-groups:create",
                    description="Create server groups for affinity/anti-affinity placement",
                    service="nova",
                    category="VM Placement",
                    label="Create Server Group",
                ),
                PolicyRule(
                    rule="nova:os_compute_api:os-server-groups:delete",
                    description="Delete server groups",
                    service="nova",
                    category="VM Placement",
                    label="Delete Server Group",
                ),
            ],
            "Data Protection": [
                PolicyRule(
                    rule="nova:os_compute_api:servers:create_image",
                    description="Create a snapshot of an instance",
                    service="nova",
                    category="Data Protection",
                    label="Create Instance Snapshot",
                ),
            ],
            "Key Pairs": [
                PolicyRule(
                    rule="nova:os_compute_api:os-keypairs:index",
                    description="List SSH key pairs",
                    service="nova",
                    category="Key Pairs",
                    label="List Key Pairs",
                ),
                PolicyRule(
                    rule="nova:os_compute_api:os-keypairs:create",
                    description="Create or import SSH key pairs",
                    service="nova",
                    category="Key Pairs",
                    label="Create Key Pair",
                ),
                PolicyRule(
                    rule="nova:os_compute_api:os-keypairs:delete",
                    description="Delete SSH key pairs",
                    service="nova",
                    category="Key Pairs",
                    label="Delete Key Pair",
                ),
            ],
            "Compute Resources": [
                PolicyRule(
                    rule="nova:os_compute_api:os-flavor-access",
                    description="List and view compute flavors",
                    service="nova",
                    category="Compute Resources",
                    label="List Flavors",
                ),
                PolicyRule(
                    rule="nova:os_compute_api:os-server-groups:index",
                    description="List server groups",
                    service="nova",
                    category="Compute Resources",
                    label="List Server Groups",
                ),
                PolicyRule(
                    rule="nova:os_compute_api:os-hypervisors:list",
                    description="List hypervisors",
                    service="nova",
                    category="Compute Resources",
                    label="List Hypervisors",
                ),
                PolicyRule(
                    rule="nova:os_compute_api:os-aggregates:index",
                    description="List host aggregates",
                    service="nova",
                    category="Compute Resources",
                    label="List Aggregates",
                ),
            ],
        },
    ),
    ServicePolicies(
        service="cinder",
        service_label="Block Storage",
        categories={
            "Volumes": [
                PolicyRule(
                    rule="cinder:volume:get_all",
                    description="List block storage volumes",
                    service="cinder",
                    category="Volumes",
                    label="List Volumes",
                ),
                PolicyRule(
                    rule="cinder:volume:get",
                    description="View block storage volume details",
                    service="cinder",
                    category="Volumes",
                    label="View Volume Details",
                ),
                PolicyRule(
                    rule="cinder:volume:create",
                    description="Create block storage volumes",
                    service="cinder",
                    category="Volumes",
                    label="Create Volume",
                ),
                PolicyRule(
                    rule="cinder:volume:delete",
                    description="Delete block storage volumes",
                    service="cinder",
                    category="Volumes",
                    label="Delete Volume",
                ),
                PolicyRule(
                    rule="cinder:volume:extend",
                    description="Extend volume size",
                    service="cinder",
                    category="Volumes",
                    label="Extend Volume",
                ),
                PolicyRule(
                    rule="cinder:volume:update",
                    description="Edit volume name and description",
                    service="cinder",
                    category="Volumes",
                    label="Edit Volume",
                ),
                PolicyRule(
                    rule="cinder:volume:retype",
                    description="Change volume type (e.g. SSD to HDD)",
                    service="cinder",
                    category="Volumes",
                    label="Change Volume Type",
                ),
            ],
            "Volume Snapshots": [
                PolicyRule(
                    rule="cinder:volume:get_all_snapshots",
                    description="List volume snapshots",
                    service="cinder",
                    category="Volume Snapshots",
                    label="List Volume Snapshots",
                ),
                PolicyRule(
                    rule="cinder:volume:create_snapshot",
                    description="Create a point-in-time snapshot of a volume",
                    service="cinder",
                    category="Volume Snapshots",
                    label="Create Volume Snapshot",
                ),
                PolicyRule(
                    rule="cinder:volume:delete_snapshot",
                    description="Delete a volume snapshot",
                    service="cinder",
                    category="Volume Snapshots",
                    label="Delete Volume Snapshot",
                ),
            ],
            "Backups": [
                PolicyRule(
                    rule="cinder:backup:get_all",
                    description="List volume backups",
                    service="cinder",
                    category="Backups",
                    label="List Backups",
                ),
                PolicyRule(
                    rule="cinder:backup:create",
                    description="Create volume backup to external target",
                    service="cinder",
                    category="Backups",
                    label="Create Backup",
                ),
                PolicyRule(
                    rule="cinder:backup:restore",
                    description="Restore volume from backup",
                    service="cinder",
                    category="Backups",
                    label="Restore Backup",
                ),
                PolicyRule(
                    rule="cinder:backup:delete",
                    description="Delete a volume backup",
                    service="cinder",
                    category="Backups",
                    label="Delete Backup",
                ),
            ],
            "Volume Transfers": [
                PolicyRule(
                    rule="cinder:volume:create_transfer",
                    description="Create a volume transfer to another project",
                    service="cinder",
                    category="Volume Transfers",
                    label="Create Volume Transfer",
                ),
                PolicyRule(
                    rule="cinder:volume:accept_transfer",
                    description="Accept a volume transfer from another project",
                    service="cinder",
                    category="Volume Transfers",
                    label="Accept Volume Transfer",
                ),
            ],
        },
    ),
    ServicePolicies(
        service="neutron",
        service_label="Networking",
        categories={
            "Networks": [
                PolicyRule(
                    rule="neutron:get_network",
                    description="List virtual networks",
                    service="neutron",
                    category="Networks",
                    label="List Networks",
                ),
                PolicyRule(
                    rule="neutron:get_subnet",
                    description="List subnets",
                    service="neutron",
                    category="Networks",
                    label="List Subnets",
                ),
                PolicyRule(
                    rule="neutron:create_network",
                    description="Create virtual networks",
                    service="neutron",
                    category="Networks",
                    label="Create Network",
                ),
                PolicyRule(
                    rule="neutron:delete_network",
                    description="Delete virtual networks",
                    service="neutron",
                    category="Networks",
                    label="Delete Network",
                ),
                PolicyRule(
                    rule="neutron:create_subnet",
                    description="Create subnets within a network",
                    service="neutron",
                    category="Networks",
                    label="Create Subnet",
                ),
                PolicyRule(
                    rule="neutron:delete_subnet",
                    description="Delete subnets",
                    service="neutron",
                    category="Networks",
                    label="Delete Subnet",
                ),
            ],
            "Routers": [
                PolicyRule(
                    rule="neutron:get_router",
                    description="List virtual routers",
                    service="neutron",
                    category="Routers",
                    label="List Routers",
                ),
                PolicyRule(
                    rule="neutron:create_router",
                    description="Create virtual routers",
                    service="neutron",
                    category="Routers",
                    label="Create Router",
                ),
                PolicyRule(
                    rule="neutron:delete_router",
                    description="Delete virtual routers",
                    service="neutron",
                    category="Routers",
                    label="Delete Router",
                ),
                PolicyRule(
                    rule="neutron:update_router",
                    description="Edit router settings and gateway",
                    service="neutron",
                    category="Routers",
                    label="Edit Router",
                ),
            ],
            "Floating IPs": [
                PolicyRule(
                    rule="neutron:get_floatingip",
                    description="List floating IP addresses",
                    service="neutron",
                    category="Floating IPs",
                    label="List Floating IPs",
                ),
                PolicyRule(
                    rule="neutron:create_floatingip",
                    description="Allocate floating IP addresses",
                    service="neutron",
                    category="Floating IPs",
                    label="Allocate Floating IP",
                ),
                PolicyRule(
                    rule="neutron:update_floatingip",
                    description="Associate/disassociate floating IP to instance",
                    service="neutron",
                    category="Floating IPs",
                    label="Associate Floating IP",
                ),
                PolicyRule(
                    rule="neutron:delete_floatingip",
                    description="Release floating IP addresses",
                    service="neutron",
                    category="Floating IPs",
                    label="Release Floating IP",
                ),
            ],
            "Security Groups": [
                PolicyRule(
                    rule="neutron:get_security_group",
                    description="List firewall security groups",
                    service="neutron",
                    category="Security Groups",
                    label="List Security Groups",
                ),
                PolicyRule(
                    rule="neutron:get_security_group_rule",
                    description="List security group rules",
                    service="neutron",
                    category="Security Groups",
                    label="List Security Group Rules",
                ),
                PolicyRule(
                    rule="neutron:create_security_group",
                    description="Create firewall security groups",
                    service="neutron",
                    category="Security Groups",
                    label="Create Security Group",
                ),
                PolicyRule(
                    rule="neutron:delete_security_group",
                    description="Delete security groups",
                    service="neutron",
                    category="Security Groups",
                    label="Delete Security Group",
                ),
                PolicyRule(
                    rule="neutron:create_security_group_rule",
                    description="Add rules to security groups",
                    service="neutron",
                    category="Security Groups",
                    label="Create Security Group Rule",
                ),
                PolicyRule(
                    rule="neutron:delete_security_group_rule",
                    description="Remove rules from security groups",
                    service="neutron",
                    category="Security Groups",
                    label="Delete Security Group Rule",
                ),
            ],
            "Ports": [
                PolicyRule(
                    rule="neutron:get_port",
                    description="List network ports",
                    service="neutron",
                    category="Ports",
                    label="List Ports",
                ),
                PolicyRule(
                    rule="neutron:create_port",
                    description="Create network ports",
                    service="neutron",
                    category="Ports",
                    label="Create Port",
                ),
                PolicyRule(
                    rule="neutron:delete_port",
                    description="Delete network ports",
                    service="neutron",
                    category="Ports",
                    label="Delete Port",
                ),
            ],
        },
    ),
    ServicePolicies(
        service="glance",
        service_label="Images",
        categories={
            "Images": [
                PolicyRule(
                    rule="glance:get_images",
                    description="List available images",
                    service="glance",
                    category="Images",
                    label="List Images",
                ),
                PolicyRule(
                    rule="glance:get_image",
                    description="View image details",
                    service="glance",
                    category="Images",
                    label="View Image Details",
                ),
                PolicyRule(
                    rule="glance:add_image",
                    description="Upload new images",
                    service="glance",
                    category="Images",
                    label="Upload Image",
                ),
                PolicyRule(
                    rule="glance:delete_image",
                    description="Delete images",
                    service="glance",
                    category="Images",
                    label="Delete Image",
                ),
                PolicyRule(
                    rule="glance:modify_image",
                    description="Edit image properties and metadata",
                    service="glance",
                    category="Images",
                    label="Edit Image",
                ),
                PolicyRule(
                    rule="glance:get_members",
                    description="View image sharing members",
                    service="glance",
                    category="Images",
                    label="View Image Members",
                ),
                PolicyRule(
                    rule="glance:add_member",
                    description="Share image with another project",
                    service="glance",
                    category="Images",
                    label="Share Image",
                ),
                PolicyRule(
                    rule="glance:delete_member",
                    description="Remove image sharing with a project",
                    service="glance",
                    category="Images",
                    label="Unshare Image",
                ),
            ],
        },
    ),
    ServicePolicies(
        service="octavia",
        service_label="Load Balancer",
        categories={
            "Load Balancers": [
                PolicyRule(
                    rule="octavia:os_load-balancer_api:loadbalancer:get_all",
                    description="List load balancers",
                    service="octavia",
                    category="Load Balancers",
                    label="List Load Balancers",
                ),
                PolicyRule(
                    rule="octavia:os_load-balancer_api:loadbalancer:post",
                    description="Create a load balancer",
                    service="octavia",
                    category="Load Balancers",
                    label="Create Load Balancer",
                ),
                PolicyRule(
                    rule="octavia:os_load-balancer_api:loadbalancer:put",
                    description="Edit load balancer settings",
                    service="octavia",
                    category="Load Balancers",
                    label="Edit Load Balancer",
                ),
                PolicyRule(
                    rule="octavia:os_load-balancer_api:loadbalancer:delete",
                    description="Delete a load balancer",
                    service="octavia",
                    category="Load Balancers",
                    label="Delete Load Balancer",
                ),
            ],
            "Listeners": [
                PolicyRule(
                    rule="octavia:os_load-balancer_api:listener:post",
                    description="Create a listener on a load balancer",
                    service="octavia",
                    category="Listeners",
                    label="Create Listener",
                ),
                PolicyRule(
                    rule="octavia:os_load-balancer_api:listener:put",
                    description="Edit listener settings",
                    service="octavia",
                    category="Listeners",
                    label="Edit Listener",
                ),
                PolicyRule(
                    rule="octavia:os_load-balancer_api:listener:delete",
                    description="Delete a listener",
                    service="octavia",
                    category="Listeners",
                    label="Delete Listener",
                ),
            ],
            "Pools & Members": [
                PolicyRule(
                    rule="octavia:os_load-balancer_api:pool:post",
                    description="Create a backend pool",
                    service="octavia",
                    category="Pools & Members",
                    label="Create Pool",
                ),
                PolicyRule(
                    rule="octavia:os_load-balancer_api:pool:delete",
                    description="Delete a backend pool",
                    service="octavia",
                    category="Pools & Members",
                    label="Delete Pool",
                ),
                PolicyRule(
                    rule="octavia:os_load-balancer_api:member:post",
                    description="Add a member to a pool",
                    service="octavia",
                    category="Pools & Members",
                    label="Add Pool Member",
                ),
                PolicyRule(
                    rule="octavia:os_load-balancer_api:member:delete",
                    description="Remove a member from a pool",
                    service="octavia",
                    category="Pools & Members",
                    label="Remove Pool Member",
                ),
            ],
            "Health Monitors": [
                PolicyRule(
                    rule="octavia:os_load-balancer_api:healthmonitor:post",
                    description="Create a health monitor for a pool",
                    service="octavia",
                    category="Health Monitors",
                    label="Create Health Monitor",
                ),
                PolicyRule(
                    rule="octavia:os_load-balancer_api:healthmonitor:delete",
                    description="Delete a health monitor",
                    service="octavia",
                    category="Health Monitors",
                    label="Delete Health Monitor",
                ),
            ],
        },
    ),
    ServicePolicies(
        service="neutron",
        service_label="VPN",
        categories={
            "VPN Gateways": [
                PolicyRule(
                    rule="neutron:create_vpnservice",
                    description="Create a VPN gateway service",
                    service="neutron",
                    category="VPN Gateways",
                    label="Create VPN Gateway",
                ),
                PolicyRule(
                    rule="neutron:delete_vpnservice",
                    description="Delete a VPN gateway service",
                    service="neutron",
                    category="VPN Gateways",
                    label="Delete VPN Gateway",
                ),
                PolicyRule(
                    rule="neutron:update_vpnservice",
                    description="Edit VPN gateway settings",
                    service="neutron",
                    category="VPN Gateways",
                    label="Edit VPN Gateway",
                ),
            ],
            "IPsec Connections": [
                PolicyRule(
                    rule="neutron:create_ipsec_site_connection",
                    description="Create an IPsec site-to-site VPN connection",
                    service="neutron",
                    category="IPsec Connections",
                    label="Create IPsec Connection",
                ),
                PolicyRule(
                    rule="neutron:delete_ipsec_site_connection",
                    description="Delete an IPsec VPN connection",
                    service="neutron",
                    category="IPsec Connections",
                    label="Delete IPsec Connection",
                ),
            ],
            "VPN Policies": [
                PolicyRule(
                    rule="neutron:create_ikepolicy",
                    description="Create an IKE encryption policy",
                    service="neutron",
                    category="VPN Policies",
                    label="Create IKE Policy",
                ),
                PolicyRule(
                    rule="neutron:create_ipsecpolicy",
                    description="Create an IPsec encryption policy",
                    service="neutron",
                    category="VPN Policies",
                    label="Create IPsec Policy",
                ),
                PolicyRule(
                    rule="neutron:create_endpoint_group",
                    description="Create a VPN endpoint group",
                    service="neutron",
                    category="VPN Policies",
                    label="Create Endpoint Group",
                ),
            ],
        },
    ),
    ServicePolicies(
        service="neutron",
        service_label="Firewall",
        categories={
            "Firewall Groups": [
                PolicyRule(
                    rule="neutron:create_firewall_group",
                    description="Create a firewall group",
                    service="neutron",
                    category="Firewall Groups",
                    label="Create Firewall",
                ),
                PolicyRule(
                    rule="neutron:delete_firewall_group",
                    description="Delete a firewall group",
                    service="neutron",
                    category="Firewall Groups",
                    label="Delete Firewall",
                ),
                PolicyRule(
                    rule="neutron:update_firewall_group",
                    description="Edit firewall group and manage ports",
                    service="neutron",
                    category="Firewall Groups",
                    label="Edit Firewall",
                ),
            ],
            "Firewall Policies": [
                PolicyRule(
                    rule="neutron:create_firewall_policy",
                    description="Create a firewall policy",
                    service="neutron",
                    category="Firewall Policies",
                    label="Create Firewall Policy",
                ),
                PolicyRule(
                    rule="neutron:delete_firewall_policy",
                    description="Delete a firewall policy",
                    service="neutron",
                    category="Firewall Policies",
                    label="Delete Firewall Policy",
                ),
                PolicyRule(
                    rule="neutron:update_firewall_policy",
                    description="Edit policy and insert/remove rules",
                    service="neutron",
                    category="Firewall Policies",
                    label="Edit Firewall Policy",
                ),
            ],
            "Firewall Rules": [
                PolicyRule(
                    rule="neutron:create_firewall_rule",
                    description="Create a firewall rule",
                    service="neutron",
                    category="Firewall Rules",
                    label="Create Firewall Rule",
                ),
                PolicyRule(
                    rule="neutron:delete_firewall_rule",
                    description="Delete a firewall rule",
                    service="neutron",
                    category="Firewall Rules",
                    label="Delete Firewall Rule",
                ),
                PolicyRule(
                    rule="neutron:update_firewall_rule",
                    description="Edit a firewall rule",
                    service="neutron",
                    category="Firewall Rules",
                    label="Edit Firewall Rule",
                ),
            ],
        },
    ),
    ServicePolicies(
        service="designate",
        service_label="DNS",
        categories={
            "DNS Zones": [
                PolicyRule(
                    rule="designate:get_zones",
                    description="List DNS zones",
                    service="designate",
                    category="DNS Zones",
                    label="List DNS Zones",
                ),
                PolicyRule(
                    rule="designate:create_zone",
                    description="Create a DNS zone",
                    service="designate",
                    category="DNS Zones",
                    label="Create DNS Zone",
                ),
                PolicyRule(
                    rule="designate:delete_zone",
                    description="Delete a DNS zone",
                    service="designate",
                    category="DNS Zones",
                    label="Delete DNS Zone",
                ),
                PolicyRule(
                    rule="designate:update_zone",
                    description="Edit DNS zone settings",
                    service="designate",
                    category="DNS Zones",
                    label="Edit DNS Zone",
                ),
            ],
            "Record Sets": [
                PolicyRule(
                    rule="designate:create_recordset",
                    description="Create DNS records in a zone",
                    service="designate",
                    category="Record Sets",
                    label="Create DNS Record",
                ),
                PolicyRule(
                    rule="designate:delete_recordset",
                    description="Delete DNS records",
                    service="designate",
                    category="Record Sets",
                    label="Delete DNS Record",
                ),
                PolicyRule(
                    rule="designate:update_recordset",
                    description="Edit DNS records",
                    service="designate",
                    category="Record Sets",
                    label="Edit DNS Record",
                ),
            ],
        },
    ),
    ServicePolicies(
        service="barbican",
        service_label="Certificates & Secrets",
        categories={
            "Secrets": [
                PolicyRule(
                    rule="barbican:secrets:get",
                    description="List secrets",
                    service="barbican",
                    category="Secrets",
                    label="List Secrets",
                ),
                PolicyRule(
                    rule="barbican:secrets:post",
                    description="Create a secret (certificate, key, password)",
                    service="barbican",
                    category="Secrets",
                    label="Create Secret",
                ),
                PolicyRule(
                    rule="barbican:secrets:delete",
                    description="Delete a secret",
                    service="barbican",
                    category="Secrets",
                    label="Delete Secret",
                ),
            ],
            "Containers": [
                PolicyRule(
                    rule="barbican:containers:post",
                    description="Create a certificate container",
                    service="barbican",
                    category="Containers",
                    label="Create Certificate",
                ),
                PolicyRule(
                    rule="barbican:containers:delete",
                    description="Delete a certificate container",
                    service="barbican",
                    category="Containers",
                    label="Delete Certificate",
                ),
            ],
        },
    ),
    ServicePolicies(
        service="manilav2",
        service_label="Shared File Storage",
        categories={
            "Shares": [
                PolicyRule(
                    rule="manilav2:share:get_all",
                    description="List shared file systems",
                    service="manilav2",
                    category="Shares",
                    label="List Shares",
                ),
                PolicyRule(
                    rule="manilav2:share:create",
                    description="Create a shared file system",
                    service="manilav2",
                    category="Shares",
                    label="Create Share",
                ),
                PolicyRule(
                    rule="manilav2:share:delete",
                    description="Delete a shared file system",
                    service="manilav2",
                    category="Shares",
                    label="Delete Share",
                ),
                PolicyRule(
                    rule="manilav2:share:update",
                    description="Edit share name and description",
                    service="manilav2",
                    category="Shares",
                    label="Edit Share",
                ),
                PolicyRule(
                    rule="manilav2:share:extend",
                    description="Extend share size",
                    service="manilav2",
                    category="Shares",
                    label="Extend Share",
                ),
            ],
            "Access Rules": [
                PolicyRule(
                    rule="manilav2:share_access_rule:index",
                    description="Manage who can access a share (IP, user, cert)",
                    service="manilav2",
                    category="Access Rules",
                    label="Manage Share Access",
                ),
            ],
        },
    ),
    ServicePolicies(
        service="swift",
        service_label="Object Storage",
        categories={
            "Containers": [
                PolicyRule(
                    rule="swift:allCanChangePolicy",
                    description="Create object storage containers (buckets)",
                    service="swift",
                    category="Containers",
                    label="Create Container",
                ),
            ],
        },
    ),
    ServicePolicies(
        service="heat",
        service_label="Orchestration",
        categories={
            "Automation Scripts": [
                PolicyRule(
                    rule="heat:stacks:index",
                    description="List orchestration stacks",
                    service="heat",
                    category="Automation Scripts",
                    label="List Stacks",
                ),
                PolicyRule(
                    rule="heat:stacks:show",
                    description="View orchestration stack details",
                    service="heat",
                    category="Automation Scripts",
                    label="View Stack Details",
                ),
                PolicyRule(
                    rule="heat:stacks:create",
                    description="Create orchestration stacks (automation templates)",
                    service="heat",
                    category="Automation Scripts",
                    label="Create Stack",
                ),
                PolicyRule(
                    rule="heat:stacks:delete",
                    description="Delete orchestration stacks",
                    service="heat",
                    category="Automation Scripts",
                    label="Delete Stack",
                ),
                PolicyRule(
                    rule="heat:stacks:update",
                    description="Update running orchestration stacks",
                    service="heat",
                    category="Automation Scripts",
                    label="Update Stack",
                ),
            ],
        },
    ),
]


def _get_all_curated_rules(
    enabled_services: Optional[Set[str]] = None,
) -> List[PolicyRule]:
    rules = []
    for svc in CURATED_POLICIES:
        if enabled_services and svc.service not in enabled_services:
            continue
        for category_rules in svc.categories.values():
            rules.extend(category_rules)
    return rules


def _generate_target(profile: schemas.Profile) -> Dict[str, str]:
    return {
        "user_id": profile.user.id,
        "project_id": profile.project.id,
        "enforce_new_defaults": CONF.openstack.enforce_new_defaults,
        "tenant": profile.project.id,
        "trust.trustor_user_id": profile.user.id,
        "target.user.id": profile.user.id,
        "target.user.domain_id": profile.user.domain.id,
        "target.project.domain_id": profile.project.domain.id,
        "target.project.id": profile.project.id,
        "target.trust.trustor_user_id": profile.user.id,
        "target.trust.trustee_user_id": profile.user.id,
        "target.token.user_id": profile.user.id,
        "target.domain.id": profile.project.domain.id,
        "target.domain_id": profile.project.domain.id,
        "target.credential.user_id": profile.user.id,
        "target.role.domain_id": profile.project.domain.id,
        "target.group.domain_id": profile.project.domain.id,
        "target.limit.domain.id": profile.project.domain.id,
        "target.limit.project_id": profile.project.domain.id,
        "target.limit.project.domain_id": profile.project.domain.id,
        "target.container.project_id": profile.project.id,
        "target.secret.project_id": profile.project.id,
        "target.order.project_id": profile.project.id,
        "target.secret.creator_id": profile.user.id,
        "allocation.owner": profile.project.id,
        "node.lessee": profile.project.id,
        "node.owner": profile.project.id,
        "member_id": profile.project.id,
        "owner": profile.project.id,
        "domain_id": profile.project.domain.id,
        "tenant_id": profile.project.id,
    }


def _check_rule_permission(
    rule: PolicyRule,
    target: Dict[str, str],
    user_context: Dict,
) -> RolePermission:
    service = rule.rule.split(":", 1)[0]
    policy_rule = rule.rule.split(":", 1)[1]
    allowed = False
    try:
        enforcer = ENFORCER.get(service)
        if enforcer is not None:
            allowed = enforcer.authorize(policy_rule, target, user_context)
    except Exception:
        LOG.debug("Failed to check rule %s", rule.rule)
    return RolePermission(rule=rule.rule, allowed=allowed)


def _build_implied_roles_map(
    role_inferences: List,
    role_id_to_name: Dict[str, str],
) -> Dict[str, List[str]]:
    """Build a map of role_id -> list of all recursively implied role names."""
    direct_implies: Dict[str, List[str]] = defaultdict(list)
    for inference in role_inferences:
        prior = inference.get("prior_role", {})
        implies_list = inference.get("implies", [])
        prior_id = prior.get("id", "")
        for imp in implies_list:
            imp_id = imp.get("id", "")
            if prior_id and imp_id:
                direct_implies[prior_id].append(imp_id)

    result: Dict[str, List[str]] = {}
    for role_id in role_id_to_name:
        visited: Set[str] = set()
        stack = list(direct_implies.get(role_id, []))
        while stack:
            rid = stack.pop()
            if rid in visited:
                continue
            visited.add(rid)
            stack.extend(direct_implies.get(rid, []))
        result[role_id] = [
            role_id_to_name[rid]
            for rid in visited
            if rid in role_id_to_name
        ]
    return result


# ---------------------------------------------------------------------------
# RBAC Gateway: URL-to-action mapping, caching, authorize + permissions API
# ---------------------------------------------------------------------------

BUILTIN_ROLES: Set[str] = {"admin", "member", "reader", "service"}

_permissions_cache: Dict[str, Dict[str, bool]] = {}
_permissions_cache_ts: float = 0.0
_CACHE_TTL: float = 30.0

# All services that RBAC can manage (superset).
# At runtime, _get_enabled_services() filters this to only
# services registered in Keystone's service catalog.
ALL_RBAC_SERVICES = {
    "nova", "cinder", "neutron", "glance", "heat",
    "octavia", "designate", "barbican", "manilav2", "swift",
}

_enabled_services_cache: Optional[Set[str]] = None
_enabled_services_ts: float = 0.0
_SERVICES_CACHE_TTL: float = 300.0  # 5 min — services don't change often


async def _get_enabled_services() -> Set[str]:
    """Return the set of RBAC-manageable services enabled in Keystone.

    Queries the Keystone service catalog (cached 5 min) and intersects
    with ALL_RBAC_SERVICES.  Falls back to ALL_RBAC_SERVICES on error.
    """
    global _enabled_services_cache, _enabled_services_ts
    now = time.time()
    if (
        _enabled_services_cache is not None
        and now - _enabled_services_ts < _SERVICES_CACHE_TTL
    ):
        return _enabled_services_cache

    try:
        from skyline_apiserver.client.openstack.system import (
            get_endpoints,
        )
        from skyline_apiserver.config import CONF

        region = CONF.openstack.default_region
        endpoints = await get_endpoints(region)
        # endpoints keys are service names like "nova", "cinder", etc.
        enabled = ALL_RBAC_SERVICES & set(endpoints.keys())
        _enabled_services_cache = enabled
        _enabled_services_ts = now
    except Exception:
        LOG.warning("RBAC: failed to query service catalog, "
                    "using all services as fallback")
        if _enabled_services_cache is not None:
            return _enabled_services_cache
        _enabled_services_cache = ALL_RBAC_SERVICES
        _enabled_services_ts = now
    return _enabled_services_cache

URL_ACTION_PATTERNS: List[Tuple[str, str, str, str]] = [
    # Nova - List/View
    ("GET", r"/v2\.1/servers$", "nova", "os_compute_api:servers:index"),
    ("GET", r"/v2\.1/servers/detail$", "nova", "os_compute_api:servers:index"),
    ("GET", r"/v2\.1/servers/[^/]+$", "nova", "os_compute_api:servers:show"),
    # Cinder - List/View
    ("GET", r"/v3/[^/]+/volumes$", "cinder", "volume:get_all"),
    ("GET", r"/v3/[^/]+/volumes/detail$", "cinder", "volume:get_all"),
    ("GET", r"/v3/[^/]+/volumes/[^/]+$", "cinder", "volume:get"),
    ("GET", r"/v3/[^/]+/snapshots", "cinder", "volume:get_all_snapshots"),
    ("GET", r"/v3/[^/]+/backups", "cinder", "backup:get_all"),
    # Neutron - List/View
    ("GET", r"/v2\.0/networks$", "neutron", "get_network"),
    ("GET", r"/v2\.0/networks/[^/]+$", "neutron", "get_network"),
    ("GET", r"/v2\.0/subnets", "neutron", "get_subnet"),
    ("GET", r"/v2\.0/routers$", "neutron", "get_router"),
    ("GET", r"/v2\.0/routers/[^/]+$", "neutron", "get_router"),
    ("GET", r"/v2\.0/floatingips", "neutron", "get_floatingip"),
    ("GET", r"/v2\.0/security-groups", "neutron", "get_security_group"),
    ("GET", r"/v2\.0/security-group-rules", "neutron", "get_security_group_rule"),
    ("GET", r"/v2\.0/ports$", "neutron", "get_port"),
    ("GET", r"/v2\.0/ports/[^/]+$", "neutron", "get_port"),
    # Nova - List/View
    ("GET", r"/v2\.1/flavors", "nova", "os_compute_api:os-flavor-access"),
    ("GET", r"/v2\.1/os-keypairs", "nova", "os_compute_api:os-keypairs:index"),
    ("GET", r"/v2\.1/os-server-groups", "nova", "os_compute_api:os-server-groups:index"),
    ("GET", r"/v2\.1/os-hypervisors", "nova", "os_compute_api:os-hypervisors:list"),
    ("GET", r"/v2\.1/os-aggregates", "nova", "os_compute_api:os-aggregates:index"),
    ("GET", r"/v2\.1/os-availability-zone", "nova", "os_compute_api:os-availability-zone:list"),
    # Glance - List/View
    ("GET", r"/v2/images$", "glance", "get_images"),
    ("GET", r"/v2/images/[^/]+$", "glance", "get_image"),
    # Octavia - List/View
    ("GET", r"/v2\.0/lbaas/loadbalancers$", "octavia", "os_load-balancer_api:loadbalancer:get_all"),
    # Heat - List/View
    ("GET", r"/v1/[^/]+/stacks$", "heat", "stacks:index"),
    ("GET", r"/v1/[^/]+/stacks/[^/]+/[^/]+$", "heat", "stacks:show"),
    # Designate - List/View
    ("GET", r"/v2/zones$", "designate", "get_zones"),
    # Barbican - List/View
    ("GET", r"/v1/secrets$", "barbican", "secrets:get"),
    # Manila - List/View
    ("GET", r"/v2/[^/]+/shares$", "manilav2", "share:get_all"),
    # Nova - Instance Lifecycle
    ("POST", r"/v2\.1/servers$", "nova", "os_compute_api:servers:create"),
    ("DELETE", r"/v2\.1/servers/[^/]+$", "nova", "os_compute_api:servers:delete"),
    ("PUT", r"/v2\.1/servers/[^/]+$", "nova", "os_compute_api:servers:update"),
    ("POST", r"/v2\.1/servers/[^/]+/remote-consoles$", "nova", "os_compute_api:os-remote-consoles:create"),
    # Nova - Attach/Detach
    ("POST", r"/v2\.1/servers/[^/]+/os-volume_attachments$", "nova", "os_compute_api:os-volumes-attachments:create"),
    ("DELETE", r"/v2\.1/servers/[^/]+/os-volume_attachments/[^/]+$", "nova", "os_compute_api:os-volumes-attachments:delete"),
    ("POST", r"/v2\.1/servers/[^/]+/os-interface$", "nova", "os_compute_api:os-attach-interfaces:create"),
    ("DELETE", r"/v2\.1/servers/[^/]+/os-interface/[^/]+$", "nova", "os_compute_api:os-attach-interfaces:delete"),
    # Nova - Server Groups
    ("POST", r"/v2\.1/os-server-groups$", "nova", "os_compute_api:os-server-groups:create"),
    ("DELETE", r"/v2\.1/os-server-groups/[^/]+$", "nova", "os_compute_api:os-server-groups:delete"),
    # Nova - Key Pairs
    ("POST", r"/v2\.1/os-keypairs$", "nova", "os_compute_api:os-keypairs:create"),
    ("DELETE", r"/v2\.1/os-keypairs/[^/]+$", "nova", "os_compute_api:os-keypairs:delete"),
    # Cinder - Volumes
    ("POST", r"/v3/[^/]+/volumes$", "cinder", "volume:create"),
    ("DELETE", r"/v3/[^/]+/volumes/[^/]+$", "cinder", "volume:delete"),
    ("PUT", r"/v3/[^/]+/volumes/[^/]+$", "cinder", "volume:update"),
    # Cinder - Snapshots
    ("POST", r"/v3/[^/]+/snapshots$", "cinder", "volume:create_snapshot"),
    ("DELETE", r"/v3/[^/]+/snapshots/[^/]+$", "cinder", "volume:delete_snapshot"),
    # Cinder - Backups
    ("POST", r"/v3/[^/]+/backups$", "cinder", "backup:create"),
    ("DELETE", r"/v3/[^/]+/backups/[^/]+$", "cinder", "backup:delete"),
    # Cinder - Transfers
    ("POST", r"/v3/[^/]+/volume-transfers$", "cinder", "volume:create_transfer"),
    ("POST", r"/v3/[^/]+/volume-transfers/[^/]+/accept$", "cinder", "volume:accept_transfer"),
    # Neutron - Networks
    ("POST", r"/v2\.0/networks$", "neutron", "create_network"),
    ("DELETE", r"/v2\.0/networks/[^/]+$", "neutron", "delete_network"),
    ("POST", r"/v2\.0/subnets$", "neutron", "create_subnet"),
    ("DELETE", r"/v2\.0/subnets/[^/]+$", "neutron", "delete_subnet"),
    # Neutron - Routers
    ("POST", r"/v2\.0/routers$", "neutron", "create_router"),
    ("DELETE", r"/v2\.0/routers/[^/]+$", "neutron", "delete_router"),
    ("PUT", r"/v2\.0/routers/[^/]+$", "neutron", "update_router"),
    # Neutron - Floating IPs
    ("POST", r"/v2\.0/floatingips$", "neutron", "create_floatingip"),
    ("PUT", r"/v2\.0/floatingips/[^/]+$", "neutron", "update_floatingip"),
    ("DELETE", r"/v2\.0/floatingips/[^/]+$", "neutron", "delete_floatingip"),
    # Neutron - Security Groups
    ("POST", r"/v2\.0/security-groups$", "neutron", "create_security_group"),
    ("DELETE", r"/v2\.0/security-groups/[^/]+$", "neutron", "delete_security_group"),
    ("POST", r"/v2\.0/security-group-rules$", "neutron", "create_security_group_rule"),
    ("DELETE", r"/v2\.0/security-group-rules/[^/]+$", "neutron", "delete_security_group_rule"),
    # Neutron - Ports
    ("POST", r"/v2\.0/ports$", "neutron", "create_port"),
    ("DELETE", r"/v2\.0/ports/[^/]+$", "neutron", "delete_port"),
    # Neutron - VPN
    ("POST", r"/v2\.0/vpn/vpnservices$", "neutron", "create_vpnservice"),
    ("DELETE", r"/v2\.0/vpn/vpnservices/[^/]+$", "neutron", "delete_vpnservice"),
    ("PUT", r"/v2\.0/vpn/vpnservices/[^/]+$", "neutron", "update_vpnservice"),
    ("POST", r"/v2\.0/vpn/ipsec-site-connections$", "neutron", "create_ipsec_site_connection"),
    ("DELETE", r"/v2\.0/vpn/ipsec-site-connections/[^/]+$", "neutron", "delete_ipsec_site_connection"),
    ("POST", r"/v2\.0/vpn/ikepolicies$", "neutron", "create_ikepolicy"),
    ("POST", r"/v2\.0/vpn/ipsecpolicies$", "neutron", "create_ipsecpolicy"),
    ("POST", r"/v2\.0/vpn/endpoint-groups$", "neutron", "create_endpoint_group"),
    # Neutron - Firewall
    ("POST", r"/v2\.0/fwaas/firewall_groups$", "neutron", "create_firewall_group"),
    ("DELETE", r"/v2\.0/fwaas/firewall_groups/[^/]+$", "neutron", "delete_firewall_group"),
    ("PUT", r"/v2\.0/fwaas/firewall_groups/[^/]+$", "neutron", "update_firewall_group"),
    ("POST", r"/v2\.0/fwaas/firewall_policies$", "neutron", "create_firewall_policy"),
    ("DELETE", r"/v2\.0/fwaas/firewall_policies/[^/]+$", "neutron", "delete_firewall_policy"),
    ("PUT", r"/v2\.0/fwaas/firewall_policies/[^/]+$", "neutron", "update_firewall_policy"),
    ("POST", r"/v2\.0/fwaas/firewall_rules$", "neutron", "create_firewall_rule"),
    ("DELETE", r"/v2\.0/fwaas/firewall_rules/[^/]+$", "neutron", "delete_firewall_rule"),
    ("PUT", r"/v2\.0/fwaas/firewall_rules/[^/]+$", "neutron", "update_firewall_rule"),
    # Octavia - Load Balancers
    ("POST", r"/v2\.0/lbaas/loadbalancers$", "octavia", "os_load-balancer_api:loadbalancer:post"),
    ("PUT", r"/v2\.0/lbaas/loadbalancers/[^/]+$", "octavia", "os_load-balancer_api:loadbalancer:put"),
    ("DELETE", r"/v2\.0/lbaas/loadbalancers/[^/]+$", "octavia", "os_load-balancer_api:loadbalancer:delete"),
    ("POST", r"/v2\.0/lbaas/listeners$", "octavia", "os_load-balancer_api:listener:post"),
    ("PUT", r"/v2\.0/lbaas/listeners/[^/]+$", "octavia", "os_load-balancer_api:listener:put"),
    ("DELETE", r"/v2\.0/lbaas/listeners/[^/]+$", "octavia", "os_load-balancer_api:listener:delete"),
    ("POST", r"/v2\.0/lbaas/pools$", "octavia", "os_load-balancer_api:pool:post"),
    ("DELETE", r"/v2\.0/lbaas/pools/[^/]+$", "octavia", "os_load-balancer_api:pool:delete"),
    ("POST", r"/v2\.0/lbaas/pools/[^/]+/members$", "octavia", "os_load-balancer_api:member:post"),
    ("DELETE", r"/v2\.0/lbaas/pools/[^/]+/members/[^/]+$", "octavia", "os_load-balancer_api:member:delete"),
    ("POST", r"/v2\.0/lbaas/healthmonitors$", "octavia", "os_load-balancer_api:healthmonitor:post"),
    ("DELETE", r"/v2\.0/lbaas/healthmonitors/[^/]+$", "octavia", "os_load-balancer_api:healthmonitor:delete"),
    # Glance - Images
    ("POST", r"/v2/images$", "glance", "add_image"),
    ("DELETE", r"/v2/images/[^/]+$", "glance", "delete_image"),
    ("PATCH", r"/v2/images/[^/]+$", "glance", "modify_image"),
    ("POST", r"/v2/images/[^/]+/members$", "glance", "add_member"),
    ("DELETE", r"/v2/images/[^/]+/members/[^/]+$", "glance", "delete_member"),
    # Designate - DNS
    ("POST", r"/v2/zones$", "designate", "create_zone"),
    ("DELETE", r"/v2/zones/[^/]+$", "designate", "delete_zone"),
    ("PATCH", r"/v2/zones/[^/]+$", "designate", "update_zone"),
    ("POST", r"/v2/zones/[^/]+/recordsets$", "designate", "create_recordset"),
    ("DELETE", r"/v2/zones/[^/]+/recordsets/[^/]+$", "designate", "delete_recordset"),
    ("PUT", r"/v2/zones/[^/]+/recordsets/[^/]+$", "designate", "update_recordset"),
    # Barbican - Secrets & Containers
    ("POST", r"/v1/secrets$", "barbican", "secrets:post"),
    ("DELETE", r"/v1/secrets/[^/]+$", "barbican", "secrets:delete"),
    ("POST", r"/v1/containers$", "barbican", "containers:post"),
    ("DELETE", r"/v1/containers/[^/]+$", "barbican", "containers:delete"),
    # Manila - Shares
    ("POST", r"/v2/[^/]+/shares$", "manilav2", "share:create"),
    ("DELETE", r"/v2/[^/]+/shares/[^/]+$", "manilav2", "share:delete"),
    ("PUT", r"/v2/[^/]+/shares/[^/]+$", "manilav2", "share:update"),
    # Heat - Stacks
    ("POST", r"/v1/[^/]+/stacks$", "heat", "stacks:create"),
    ("DELETE", r"/v1/[^/]+/stacks/[^/]+/[^/]+$", "heat", "stacks:delete"),
    ("PUT", r"/v1/[^/]+/stacks/[^/]+/[^/]+$", "heat", "stacks:update"),
]

_COMPILED_PATTERNS = [
    (m, re.compile(p), s, a) for m, p, s, a in URL_ACTION_PATTERNS
]


def _extract_service_name(uri: str) -> Optional[str]:
    """Extract service name from URI like /api/openstack/regionone/nova/v2.1/..."""
    parts = uri.split("/")
    if len(parts) >= 5 and parts[1] == "api" and parts[2] == "openstack":
        return parts[4]
    return None


def _extract_api_path(uri: str) -> Optional[str]:
    # Strip query parameters before extracting path
    clean_uri = uri.split("?")[0]
    parts = clean_uri.split("/")
    if len(parts) >= 5 and parts[1] == "api" and parts[2] == "openstack":
        return "/" + "/".join(parts[5:])
    return None


def _match_url_to_action(
    method: str,
    api_path: str,
) -> Optional[Tuple[str, str]]:
    for pat_method, pat_regex, service, action in _COMPILED_PATTERNS:
        if method == pat_method and pat_regex.search(api_path):
            return (service, action)
    return None


async def _get_cached_permissions() -> Dict[str, Dict[str, bool]]:
    global _permissions_cache, _permissions_cache_ts
    now = time.time()
    if now - _permissions_cache_ts < _CACHE_TTL and _permissions_cache:
        return _permissions_cache

    try:
        rows = await db_api.get_all_custom_permissions()
        cache: Dict[str, Dict[str, bool]] = {}
        for row in rows:
            role = row["role_name"]
            key = f"{row['service']}:{row['action']}"
            if role not in cache:
                cache[role] = {}
            cache[role][key] = bool(row["allowed"])
        _permissions_cache = cache
        _permissions_cache_ts = now
    except Exception:
        LOG.warning("Failed to load RBAC permissions from database")
    return _permissions_cache


def _invalidate_permissions_cache() -> None:
    global _permissions_cache_ts
    _permissions_cache_ts = 0.0


# Nova server actions allowed even when license is expired
_LICENSE_ALLOWED_ACTIONS = {
    "os-stop", "os-start", "stop", "start",
    "reboot", "os-reboot",
    "pause", "unpause",
    "suspend", "resume",
    "os-getConsoleOutput", "os-getVNCConsole",
    "os-getSPICEConsole", "os-getRDPConsole",
    "lock", "unlock",
}


def _is_allowed_expired_action(uri: str, method: str) -> bool:
    """Check if this is a power/console action allowed when license expired."""
    if method != "POST":
        return False
    # Nova server actions are POST to .../servers/{id}/action
    if "/action" not in uri:
        return False
    # The action body is not available here (auth_request doesn't forward body).
    # But the URL pattern /servers/{uuid}/action is only used for server actions,
    # and all server actions are either allowed (power) or blocked (resize/rebuild).
    # Since we can't inspect the body, allow /action URLs and rely on the frontend
    # guard + LicenseMiddleware for the fine-grained action check.
    return True


async def _check_license_for_proxy(method: str, uri: str) -> None:
    """Block mutating OpenStack API calls when license is expired."""
    if method in ("GET", "HEAD", "OPTIONS"):
        return
    try:
        from skyline_apiserver.core.license import ComplianceValidator

        state = await ComplianceValidator.get_compliance_state()
        is_expired = (
            state.get("expired", False)
            or state.get("days_remaining", 999) <= 0
            or state.get("status") == "expired"
        )
        if is_expired and not _is_allowed_expired_action(uri, method):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="LICENSE_EXPIRED: License expired. This operation is not available.",
            )
    except HTTPException:
        raise
    except Exception:
        # Fail-open: if license check fails, allow the request
        pass


@router.get(
    "/rbac/authorize",
    description="Authorization check endpoint for Nginx auth_request",
    responses={
        200: {},
        401: {},
        403: {},
    },
    status_code=status.HTTP_200_OK,
)
async def authorize(
    request: Request,
    x_original_uri: str = Header("", alias="x-original-uri"),
    x_original_method: str = Header("GET", alias="x-original-method"),
    x_auth_token: str = Header("", alias="x-auth-token"),
) -> None:
    if not x_original_uri:
        return None

    if x_original_method in ("HEAD", "OPTIONS"):
        return None

    # License enforcement: block mutating calls when expired
    await _check_license_for_proxy(x_original_method, x_original_uri)

    service_name = _extract_service_name(x_original_uri)
    if not service_name:
        return None

    try:
        from skyline_apiserver.config import CONF
        roles = set()
        # Try session cookie first (always present in Skyline browser)
        cookie_header = request.headers.get("cookie", "")
        session_name = CONF.default.session_name
        session_token = None
        for part in cookie_header.split(";"):
            part = part.strip()
            if part.startswith(f"{session_name}="):
                session_token = part[len(session_name) + 1:]
                break
        if session_token:
            from skyline_apiserver.core.security import (
                parse_access_token,
                generate_profile_by_token,
            )

            token = parse_access_token(session_token)
            profile = await generate_profile_by_token(token)
            roles = {r.name for r in profile.roles}
        elif x_auth_token:
            # Fallback to X-Auth-Token (CLI/curl)
            session = await utils.get_system_session()
            region = CONF.openstack.default_region
            token_data = await get_token_data(
                x_auth_token, region, session
            )
            roles = {
                r["name"]
                for r in token_data.get("token", {}).get("roles", [])
            }
        if not roles:
            return None
    except Exception:
        LOG.warning("RBAC authorize: failed to parse roles")
        return None

    permissions = await _get_cached_permissions()

    has_custom = any(role in permissions for role in roles)
    if not has_custom:
        return None

    enabled = await _get_enabled_services()
    if service_name not in enabled:
        return None

    role_has_service_access = False
    for role in roles:
        role_perms = permissions.get(role, {})
        if any(
            k.startswith(f"{service_name}:") and v
            for k, v in role_perms.items()
        ):
            role_has_service_access = True
            break

    if not role_has_service_access:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"No access to {service_name}",
        )

    api_path = _extract_api_path(x_original_uri)
    if not api_path:
        return None

    action_match = _match_url_to_action(x_original_method, api_path)
    if not action_match:
        return None

    action_key = f"{action_match[0]}:{action_match[1]}"
    for role in roles:
        role_perms = permissions.get(role, {})
        if role_perms.get(action_key, False):
            return None

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=f"Permission denied: {action_key}",
    )


@router.get(
    "/rbac/permissions",
    description="Get all custom role permissions from database",
    responses={
        200: {"model": AllPermissionsData},
        401: {"model": schemas.UnauthorizedMessage},
        403: {"model": schemas.ForbiddenMessage},
    },
    response_model=AllPermissionsData,
    status_code=status.HTTP_200_OK,
    response_description="OK",
)
async def get_permissions(
    profile: schemas.Profile = Depends(deps.get_profile_update_jwt),
) -> AllPermissionsData:
    assert_system_admin(profile=profile, exception="Not allowed")

    rows = await db_api.get_all_custom_permissions()
    roles_map: Dict[str, List[PermissionEntry]] = {}
    for row in rows:
        rn = row["role_name"]
        if rn not in roles_map:
            roles_map[rn] = []
        roles_map[rn].append(
            PermissionEntry(
                service=row["service"],
                action=row["action"],
                allowed=bool(row["allowed"]),
            )
        )

    return AllPermissionsData(
        roles=[
            RolePermissionsData(role_name=rn, permissions=perms)
            for rn, perms in roles_map.items()
        ]
    )


@router.put(
    "/rbac/permissions",
    description="Save permissions for a custom role (replaces all existing)",
    responses={
        200: {"model": schemas.Message},
        401: {"model": schemas.UnauthorizedMessage},
        403: {"model": schemas.ForbiddenMessage},
    },
    response_model=schemas.Message,
    status_code=status.HTTP_200_OK,
    response_description="OK",
)
async def save_permissions(
    body: RolePermissionsData,
    profile: schemas.Profile = Depends(deps.get_profile_update_jwt),
) -> schemas.Message:
    assert_system_admin(profile=profile, exception="Not allowed")

    if body.role_name in BUILTIN_ROLES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot modify permissions for built-in roles",
        )

    perms = [
        {"service": p.service, "action": p.action, "allowed": p.allowed}
        for p in body.permissions
    ]
    await db_api.batch_set_role_permissions(body.role_name, perms)
    _invalidate_permissions_cache()

    return schemas.Message(message="Permissions saved")


@router.get(
    "/rbac/registry",
    description="List curated policy rules grouped by service and category",
    responses={
        200: {"model": RBACRegistry},
        401: {"model": schemas.UnauthorizedMessage},
        403: {"model": schemas.ForbiddenMessage},
    },
    response_model=RBACRegistry,
    status_code=status.HTTP_200_OK,
    response_description="OK",
)
async def list_registry(
    profile: schemas.Profile = Depends(deps.get_profile_update_jwt),
) -> RBACRegistry:
    assert_system_admin(profile=profile, exception="Not allowed")
    enabled = await _get_enabled_services()
    filtered = [s for s in CURATED_POLICIES if s.service in enabled]
    return RBACRegistry(services=filtered)


@router.get(
    "/rbac/matrix",
    description="List curated policy rules with per-role permission checks",
    responses={
        200: {"model": RolesPermissionsMatrix},
        401: {"model": schemas.UnauthorizedMessage},
        403: {"model": schemas.ForbiddenMessage},
        500: {"model": schemas.InternalServerErrorMessage},
    },
    response_model=RolesPermissionsMatrix,
    status_code=status.HTTP_200_OK,
    response_description="OK",
)
async def list_matrix(
    profile: schemas.Profile = Depends(deps.get_profile_update_jwt),
) -> RolesPermissionsMatrix:
    assert_system_admin(profile=profile, exception="Not allowed")

    try:
        session = await utils.generate_session(profile)
        kc = await utils.keystone_client(session=session, region=profile.region)
        ks_roles = await run_in_threadpool(kc.roles.list)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )

    role_id_to_name: Dict[str, str] = {
        r.id: r.name for r in ks_roles
    }

    implied_map: Dict[str, List[str]] = {}
    try:
        if hasattr(kc.roles, "list_role_inferences"):
            raw = await run_in_threadpool(
                kc.roles.list_role_inferences
            )
            inferences = raw.get("role_inferences", [])
            implied_map = _build_implied_roles_map(
                inferences, role_id_to_name
            )
    except Exception:
        LOG.debug("Failed to fetch implied role inferences")

    target = _generate_target(profile)
    enabled = await _get_enabled_services()
    all_rules = _get_all_curated_rules(enabled)

    roles_permissions: List[RolePermissions] = []
    for ks_role in ks_roles:
        role_detail = RoleDetail(
            id=ks_role.id,
            name=ks_role.name,
            domain_id=getattr(ks_role, "domain_id", None),
            description=getattr(ks_role, "description", None),
        )

        effective_roles = [ks_role.name] + implied_map.get(
            ks_role.id, []
        )
        effective_names = set(effective_roles)

        simulated_context = {
            "roles": effective_roles,
            "is_admin": "admin" in effective_names,
            "is_reader_admin": bool(
                effective_names & {"admin", "reader"}
            ),
            "user_id": profile.user.id,
            "project_id": profile.project.id,
            "tenant_id": profile.project.id,
            "domain_id": profile.user.domain.id,
            "user_domain_id": profile.user.domain.id,
            "project_domain_id": profile.project.domain.id,
            "system_scope": "",
        }

        permissions = [
            _check_rule_permission(rule, target, simulated_context)
            for rule in all_rules
        ]
        roles_permissions.append(
            RolePermissions(role=role_detail, permissions=permissions)
        )

    enabled = await _get_enabled_services()
    filtered = [s for s in CURATED_POLICIES if s.service in enabled]
    return RolesPermissionsMatrix(
        services=filtered, roles=roles_permissions
    )


@router.get(
    "/rbac/roles",
    description="List all Keystone roles",
    responses={
        200: {"model": RolesList},
        401: {"model": schemas.UnauthorizedMessage},
        403: {"model": schemas.ForbiddenMessage},
        500: {"model": schemas.InternalServerErrorMessage},
    },
    response_model=RolesList,
    status_code=status.HTTP_200_OK,
    response_description="OK",
)
async def list_roles(
    profile: schemas.Profile = Depends(deps.get_profile_update_jwt),
) -> RolesList:
    assert_system_admin(profile=profile, exception="Not allowed")

    try:
        session = await utils.generate_session(profile)
        kc = await utils.keystone_client(session=session, region=profile.region)
        ks_roles = await run_in_threadpool(kc.roles.list)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )

    roles = [
        RoleDetail(
            id=r.id,
            name=r.name,
            domain_id=getattr(r, "domain_id", None),
            description=getattr(r, "description", None),
        )
        for r in ks_roles
    ]
    return RolesList(roles=roles)


@router.post(
    "/rbac/roles",
    description="Create a new Keystone role",
    responses={
        201: {"model": RoleDetail},
        401: {"model": schemas.UnauthorizedMessage},
        403: {"model": schemas.ForbiddenMessage},
        500: {"model": schemas.InternalServerErrorMessage},
    },
    response_model=RoleDetail,
    status_code=status.HTTP_201_CREATED,
    response_description="Created",
)
async def create_role(
    body: CreateRoleRequest,
    profile: schemas.Profile = Depends(deps.get_profile_update_jwt),
) -> RoleDetail:
    assert_system_admin(profile=profile, exception="Not allowed")

    try:
        session = await utils.generate_session(profile)
        kc = await utils.keystone_client(session=session, region=profile.region)
        kwargs = {"name": body.name}
        if body.description is not None:
            kwargs["description"] = body.description
        ks_role = await run_in_threadpool(kc.roles.create, **kwargs)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )

    return RoleDetail(
        id=ks_role.id,
        name=ks_role.name,
        domain_id=getattr(ks_role, "domain_id", None),
        description=getattr(ks_role, "description", None),
    )


@router.delete(
    "/rbac/roles/{role_id}",
    description="Delete a Keystone role",
    responses={
        204: {"model": None},
        401: {"model": schemas.UnauthorizedMessage},
        403: {"model": schemas.ForbiddenMessage},
        500: {"model": schemas.InternalServerErrorMessage},
    },
    status_code=status.HTTP_204_NO_CONTENT,
    response_description="No Content",
)
async def delete_role(
    role_id: str,
    profile: schemas.Profile = Depends(deps.get_profile_update_jwt),
) -> None:
    assert_system_admin(profile=profile, exception="Not allowed")

    try:
        session = await utils.generate_session(profile)
        kc = await utils.keystone_client(session=session, region=profile.region)
        await run_in_threadpool(kc.roles.delete, role_id)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )


@router.get(
    "/rbac/roles/{role_id}/implies",
    description="List roles implied by a given role",
    responses={
        200: {"model": ImpliedRolesList},
        401: {"model": schemas.UnauthorizedMessage},
        403: {"model": schemas.ForbiddenMessage},
        500: {"model": schemas.InternalServerErrorMessage},
    },
    response_model=ImpliedRolesList,
    status_code=status.HTTP_200_OK,
    response_description="OK",
)
async def list_implied_roles(
    role_id: str,
    profile: schemas.Profile = Depends(deps.get_profile_update_jwt),
) -> ImpliedRolesList:
    assert_system_admin(profile=profile, exception="Not allowed")

    try:
        session = await utils.generate_session(profile)
        kc = await utils.keystone_client(
            session=session, region=profile.region
        )
        if not hasattr(kc.roles, "list_role_inferences"):
            return ImpliedRolesList(implies=[])
        raw = await run_in_threadpool(kc.roles.list_role_inferences)
        inferences = raw.get("role_inferences", [])
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )

    implies = []
    for inference in inferences:
        prior = inference.get("prior_role", {})
        if prior.get("id") != role_id:
            continue
        for imp in inference.get("implies", []):
            implies.append(
                ImpliedRole(
                    prior_role_id=prior.get("id", ""),
                    prior_role_name=prior.get("name"),
                    implied_role_id=imp.get("id", ""),
                    implied_role_name=imp.get("name"),
                )
            )

    return ImpliedRolesList(implies=implies)


@router.put(
    "/rbac/roles/{role_id}/implies/{implied_role_id}",
    description="Create an implied role relationship",
    responses={
        201: {"model": None},
        401: {"model": schemas.UnauthorizedMessage},
        403: {"model": schemas.ForbiddenMessage},
        500: {"model": schemas.InternalServerErrorMessage},
    },
    status_code=status.HTTP_201_CREATED,
    response_description="Created",
)
async def create_implied_role(
    role_id: str,
    implied_role_id: str,
    profile: schemas.Profile = Depends(deps.get_profile_update_jwt),
) -> None:
    assert_system_admin(profile=profile, exception="Not allowed")

    try:
        session = await utils.generate_session(profile)
        kc = await utils.keystone_client(
            session=session, region=profile.region
        )
        await run_in_threadpool(
            kc.roles.create_implied, role_id, implied_role_id
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )


@router.delete(
    "/rbac/roles/{role_id}/implies/{implied_role_id}",
    description="Delete an implied role relationship",
    responses={
        204: {"model": None},
        401: {"model": schemas.UnauthorizedMessage},
        403: {"model": schemas.ForbiddenMessage},
        500: {"model": schemas.InternalServerErrorMessage},
    },
    status_code=status.HTTP_204_NO_CONTENT,
    response_description="No Content",
)
async def delete_implied_role(
    role_id: str,
    implied_role_id: str,
    profile: schemas.Profile = Depends(deps.get_profile_update_jwt),
) -> None:
    assert_system_admin(profile=profile, exception="Not allowed")

    try:
        session = await utils.generate_session(profile)
        kc = await utils.keystone_client(
            session=session, region=profile.region
        )
        await run_in_threadpool(
            kc.roles.delete_implied, role_id, implied_role_id
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )


@router.get(
    "/rbac/users",
    description="List all Keystone users",
    responses={
        200: {"model": UsersList},
        401: {"model": schemas.UnauthorizedMessage},
        403: {"model": schemas.ForbiddenMessage},
        500: {"model": schemas.InternalServerErrorMessage},
    },
    response_model=UsersList,
    status_code=status.HTTP_200_OK,
    response_description="OK",
)
async def list_users(
    profile: schemas.Profile = Depends(deps.get_profile_update_jwt),
) -> UsersList:
    assert_system_admin(profile=profile, exception="Not allowed")

    try:
        session = await utils.generate_session(profile)
        kc = await utils.keystone_client(session=session, region=profile.region)
        ks_users = await run_in_threadpool(kc.users.list)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )

    users = [
        UserDetail(
            id=u.id,
            name=u.name,
            domain_id=getattr(u, "domain_id", None),
            enabled=getattr(u, "enabled", None),
            email=getattr(u, "email", None),
        )
        for u in ks_users
    ]
    return UsersList(users=users)


@router.get(
    "/rbac/assignments",
    description="List all role assignments",
    responses={
        200: {"model": RoleAssignmentsList},
        401: {"model": schemas.UnauthorizedMessage},
        403: {"model": schemas.ForbiddenMessage},
        500: {"model": schemas.InternalServerErrorMessage},
    },
    response_model=RoleAssignmentsList,
    status_code=status.HTTP_200_OK,
    response_description="OK",
)
async def list_assignments(
    profile: schemas.Profile = Depends(deps.get_profile_update_jwt),
) -> RoleAssignmentsList:
    assert_system_admin(profile=profile, exception="Not allowed")

    try:
        session = await utils.generate_session(profile)
        kc = await utils.keystone_client(session=session, region=profile.region)
        # Fetch assignments WITHOUT include_names (avoids 30s+ Keystone timeout)
        # Then resolve names client-side from parallel user/role/project fetches
        ks_assignments, ks_roles, ks_users, ks_projects = await asyncio.gather(
            run_in_threadpool(kc.role_assignments.list),
            run_in_threadpool(kc.roles.list),
            run_in_threadpool(kc.users.list),
            run_in_threadpool(kc.projects.list),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )

    role_map = {r.id: r.name for r in ks_roles}
    user_map = {u.id: u.name for u in ks_users}
    project_map = {p.id: p.name for p in ks_projects}

    assignments = []
    for a in ks_assignments:
        user_info = getattr(a, "user", {}) or {}
        role_info = getattr(a, "role", {}) or {}
        scope = getattr(a, "scope", {}) or {}
        project_info = scope.get("project", {}) or {}

        uid = user_info.get("id", "")
        if not uid:
            continue

        rid = role_info.get("id", "")
        pid = project_info.get("id", "")

        assignments.append(
            RoleAssignment(
                user_id=uid,
                user_name=user_map.get(uid, uid),
                role_id=rid,
                role_name=role_map.get(rid, rid),
                project_id=pid,
                project_name=project_map.get(pid, pid),
            )
        )

    return RoleAssignmentsList(assignments=assignments)


@router.get(
    "/rbac/projects",
    description="List all Keystone projects for role assignment",
    responses={
        200: {},
        401: {"model": schemas.UnauthorizedMessage},
        403: {"model": schemas.ForbiddenMessage},
    },
    status_code=status.HTTP_200_OK,
)
async def list_projects(
    profile: schemas.Profile = Depends(deps.get_profile_update_jwt),
):
    assert_system_admin(profile=profile, exception="Not allowed")
    try:
        session = await utils.generate_session(profile)
        kc = await utils.keystone_client(session=session, region=profile.region)
        ks_projects = await run_in_threadpool(kc.projects.list)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )
    projects = [
        {"id": p.id, "name": p.name, "domain_id": getattr(p, "domain_id", None)}
        for p in ks_projects
    ]
    return {"projects": projects}


@router.post(
    "/rbac/assignments",
    description="Grant a role to a user on a project",
    responses={
        204: {"model": None},
        401: {"model": schemas.UnauthorizedMessage},
        403: {"model": schemas.ForbiddenMessage},
        500: {"model": schemas.InternalServerErrorMessage},
    },
    status_code=status.HTTP_204_NO_CONTENT,
    response_description="No Content",
)
async def grant_role(
    body: GrantRevokeRequest,
    profile: schemas.Profile = Depends(deps.get_profile_update_jwt),
) -> None:
    assert_system_admin(profile=profile, exception="Not allowed")

    try:
        session = await utils.generate_session(profile)
        kc = await utils.keystone_client(session=session, region=profile.region)
        await run_in_threadpool(
            kc.roles.grant,
            body.role_id,
            user=body.user_id,
            project=body.project_id,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )


@router.delete(
    "/rbac/assignments",
    description="Revoke a role from a user on a project",
    responses={
        204: {"model": None},
        401: {"model": schemas.UnauthorizedMessage},
        403: {"model": schemas.ForbiddenMessage},
        500: {"model": schemas.InternalServerErrorMessage},
    },
    status_code=status.HTTP_204_NO_CONTENT,
    response_description="No Content",
)
async def revoke_role(
    body: GrantRevokeRequest,
    profile: schemas.Profile = Depends(deps.get_profile_update_jwt),
) -> None:
    assert_system_admin(profile=profile, exception="Not allowed")

    try:
        session = await utils.generate_session(profile)
        kc = await utils.keystone_client(session=session, region=profile.region)
        await run_in_threadpool(
            kc.roles.revoke,
            body.role_id,
            user=body.user_id,
            project=body.project_id,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )
