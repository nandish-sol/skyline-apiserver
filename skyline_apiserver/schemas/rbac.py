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

from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class PolicyRule(BaseModel):
    rule: str = Field(..., description="Policy rule name")
    description: str = Field(..., description="Human-readable description")
    service: str = Field(..., description="Service name")
    category: str = Field(..., description="Category within the service")
    label: str = Field(..., description="Human-readable short label")


class ServicePolicies(BaseModel):
    service: str = Field(..., description="Service name")
    service_label: str = Field(..., description="Human-readable service label")
    categories: Dict[str, List[PolicyRule]] = Field(
        ..., description="Rules grouped by category"
    )


class RBACRegistry(BaseModel):
    services: List[ServicePolicies] = Field(
        ..., description="All services with their curated rules"
    )


class RolePermission(BaseModel):
    rule: str = Field(..., description="Policy rule name")
    allowed: bool = Field(..., description="Whether the role allows this action")


class RoleDetail(BaseModel):
    id: str = Field(..., description="Role ID")
    name: str = Field(..., description="Role name")
    domain_id: Optional[str] = Field(None, description="Domain ID")
    description: Optional[str] = Field(None, description="Role description")


class RolesList(BaseModel):
    roles: List[RoleDetail] = Field(..., description="List of roles")


class RolePermissions(BaseModel):
    role: RoleDetail = Field(..., description="Role details")
    permissions: List[RolePermission] = Field(
        ..., description="Permissions for this role"
    )


class RolesPermissionsMatrix(BaseModel):
    services: List[ServicePolicies] = Field(..., description="Policy registry")
    roles: List[RolePermissions] = Field(..., description="Permissions per role")


class CreateRoleRequest(BaseModel):
    name: str = Field(..., description="Role name")
    description: Optional[str] = Field(None, description="Role description")


class RoleAssignment(BaseModel):
    user_id: str = Field(..., description="User ID")
    user_name: Optional[str] = Field(None, description="User name")
    role_id: str = Field(..., description="Role ID")
    role_name: Optional[str] = Field(None, description="Role name")
    project_id: Optional[str] = Field(None, description="Project ID")
    project_name: Optional[str] = Field(None, description="Project name")


class RoleAssignmentsList(BaseModel):
    assignments: List[RoleAssignment] = Field(..., description="Role assignments")


class GrantRevokeRequest(BaseModel):
    user_id: str = Field(..., description="User ID")
    role_id: str = Field(..., description="Role ID")
    project_id: str = Field(..., description="Project ID")


class UserDetail(BaseModel):
    id: str = Field(..., description="User ID")
    name: str = Field(..., description="Username")
    domain_id: Optional[str] = Field(None, description="Domain ID")
    enabled: Optional[bool] = Field(None, description="Whether user is enabled")
    email: Optional[str] = Field(None, description="Email address")


class UsersList(BaseModel):
    users: List[UserDetail] = Field(..., description="List of users")


class ImpliedRole(BaseModel):
    prior_role_id: str = Field(..., description="Role that implies another")
    prior_role_name: Optional[str] = Field(None, description="Name of prior role")
    implied_role_id: str = Field(..., description="Role being implied")
    implied_role_name: Optional[str] = Field(None, description="Name of implied role")


class ImpliedRolesList(BaseModel):
    implies: List[ImpliedRole] = Field(..., description="List of implied role relationships")


class PermissionEntry(BaseModel):
    service: str = Field(..., description="Service name")
    action: str = Field(..., description="Action name")
    allowed: bool = Field(..., description="Whether allowed")


class RolePermissionsData(BaseModel):
    role_name: str = Field(..., description="Role name")
    permissions: List[PermissionEntry] = Field(..., description="Permission entries")


class AllPermissionsData(BaseModel):
    roles: List[RolePermissionsData] = Field(
        ..., description="All custom role permissions"
    )
