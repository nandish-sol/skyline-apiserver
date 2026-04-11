# Copyright 2022 99cloud
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

import time as _time

from fastapi import APIRouter, Depends, HTTPException, Query, status
from httpx import codes

from skyline_apiserver import schemas
from skyline_apiserver.api import deps
from skyline_apiserver.config import CONF
from skyline_apiserver.core import local_stats
from skyline_apiserver.log import LOG
from skyline_apiserver.types import constants
from skyline_apiserver.utils.httpclient import _http_request
from skyline_apiserver.utils.roles import is_system_admin_or_reader

router = APIRouter()


def _use_local_fallback() -> bool:
    """True when the local-stats shim should answer instead of upstream Prometheus.

    Triggers when `prometheus_endpoint` is unset/empty/placeholder and the
    `prometheus_local_fallback` config option is enabled. Multi-node clusters
    with real Prometheus keep the endpoint set and never hit this path.
    """
    endpoint = (CONF.default.prometheus_endpoint or "").strip().rstrip("/")
    if endpoint in ("", "local", "http://localhost:9091", "http://127.0.0.1:9091"):
        return bool(getattr(CONF.default, "prometheus_local_fallback", True))
    return False


def get_prometheus_query_response(
    resp: dict,
    profile: schemas.Profile,
) -> schemas.PrometheusQueryResponse:
    ret = schemas.PrometheusQueryResponse(status=resp["status"])
    if "warnings" in resp:
        ret.warnings = resp["warnings"]
    if "errorType" in resp:
        ret.errorType = resp["errorType"]
    if "error" in resp:
        ret.error = resp["error"]
    if "data" in resp:
        result = [
            schemas.PrometheusQueryResult(metric=i["metric"], value=i["value"])
            for i in resp["data"]["result"]
        ]

        if not is_system_admin_or_reader(profile):
            result = [
                i
                for i in result
                if "project_id" in i.metric and i.metric["project_id"] == profile.project.id
            ]

        data = schemas.PrometheusQueryData(
            resultType=resp["data"]["resultType"],
            result=result,
        )
        ret.data = data

    return ret


def get_prometheus_query_range_response(
    resp: dict,
    profile: schemas.Profile,
) -> schemas.PrometheusQueryRangeResponse:
    ret = schemas.PrometheusQueryRangeResponse(status=resp["status"])
    if "warnings" in resp:
        ret.warnings = resp["warnings"]
    if "errorType" in resp:
        ret.errorType = resp["errorType"]
    if "error" in resp:
        ret.error = resp["error"]
    if "data" in resp:
        result = [
            schemas.PrometheusQueryRangeResult(metric=i["metric"], value=i["values"])
            for i in resp["data"]["result"]
        ]

        if not is_system_admin_or_reader(profile):
            result = [
                i
                for i in result
                if "project_id" in i.metric and i.metric["project_id"] == profile.project.id
            ]

        data = schemas.PrometheusQueryRangeData(
            resultType=resp["data"]["resultType"],
            result=result,
        )
        ret.data = data

    return ret


@router.get(
    "/query",
    description="Prometheus query API.",
    responses={
        200: {"model": schemas.PrometheusQueryResponse},
        401: {"model": schemas.UnauthorizedMessage},
        500: {"model": schemas.InternalServerErrorMessage},
    },
    response_model=schemas.PrometheusQueryResponse,
    status_code=status.HTTP_200_OK,
    response_description="OK",
    response_model_exclude_none=True,
)
async def prometheus_query(
    query: str = Query(None, description="The query expression of prometheus to filter."),
    time: str = Query(None, description="The time to filter."),
    timeout: str = Query(None, description="The timeout to filter."),
    profile: schemas.Profile = Depends(deps.get_profile_update_jwt),
) -> schemas.PrometheusQueryResponse:
    if _use_local_fallback():
        try:
            ts = float(time) if time else _time.time()
        except (TypeError, ValueError):
            ts = _time.time()
        local_resp = local_stats.resolve_query(query or "", ts)
        return get_prometheus_query_response(local_resp, profile)

    kwargs = {}
    if query is not None:
        kwargs["query"] = query
    if time is not None:
        kwargs["time"] = time
    if timeout is not None:
        kwargs["timeout"] = timeout

    auth = None
    if CONF.default.prometheus_enable_basic_auth:
        auth = (
            CONF.default.prometheus_basic_auth_user,
            CONF.default.prometheus_basic_auth_password,
        )
    try:
        resp = await _http_request(
            url=CONF.default.prometheus_endpoint + constants.PROMETHEUS_QUERY_API,
            params=kwargs,
            auth=auth,
        )
    except Exception as exc:
        LOG.warning("prometheus upstream unreachable ({}) — falling back to local shim", exc)
        local_resp = local_stats.resolve_query(query or "", _time.time())
        return get_prometheus_query_response(local_resp, profile)

    if resp.status_code != codes.OK:
        LOG.warning(
            "prometheus upstream returned {} — falling back to local shim",
            resp.status_code,
        )
        local_resp = local_stats.resolve_query(query or "", _time.time())
        return get_prometheus_query_response(local_resp, profile)

    return get_prometheus_query_response(resp.json(), profile)


@router.get(
    "/query_range",
    description="Prometheus query_range API.",
    responses={
        200: {"model": schemas.PrometheusQueryRangeResponse},
        401: {"model": schemas.UnauthorizedMessage},
        500: {"model": schemas.InternalServerErrorMessage},
    },
    response_model=schemas.PrometheusQueryRangeResponse,
    status_code=status.HTTP_200_OK,
    response_description="OK",
    response_model_exclude_none=True,
)
async def prometheus_query_range(
    query: str = Query(None, description="The query expression of prometheus to filter."),
    start: str = Query(None, description="The start time to filter."),
    end: str = Query(None, description="The end time to filter."),
    step: str = Query(None, description="The step to filter."),
    timeout: str = Query(None, description="The timeout to filter."),
    profile: schemas.Profile = Depends(deps.get_profile_update_jwt),
) -> schemas.PrometheusQueryRangeResponse:
    def _parse_ts(v, default):
        try:
            return float(v) if v else default
        except (TypeError, ValueError):
            return default

    if _use_local_fallback():
        end_ts = _parse_ts(end, _time.time())
        start_ts = _parse_ts(start, end_ts - 600.0)
        step_s = _parse_ts(step, 15.0)
        local_resp = local_stats.resolve_query_range(
            query or "", start_ts, end_ts, step_s
        )
        return get_prometheus_query_range_response(local_resp, profile)

    kwargs = {}
    if query is not None:
        kwargs["query"] = query
    if start is not None:
        kwargs["start"] = start
    if end is not None:
        kwargs["end"] = end
    if step is not None:
        kwargs["step"] = step
    if timeout is not None:
        kwargs["timeout"] = timeout

    auth = None
    if CONF.default.prometheus_enable_basic_auth:
        auth = (
            CONF.default.prometheus_basic_auth_user,
            CONF.default.prometheus_basic_auth_password,
        )
    try:
        resp = await _http_request(
            url=CONF.default.prometheus_endpoint + constants.PROMETHEUS_QUERY_RANGE_API,
            params=kwargs,
            auth=auth,
        )
    except Exception as exc:
        LOG.warning(
            "prometheus upstream unreachable ({}) — falling back to local shim", exc,
        )
        end_ts = _parse_ts(end, _time.time())
        start_ts = _parse_ts(start, end_ts - 600.0)
        step_s = _parse_ts(step, 15.0)
        local_resp = local_stats.resolve_query_range(
            query or "", start_ts, end_ts, step_s
        )
        return get_prometheus_query_range_response(local_resp, profile)

    if resp.status_code != codes.OK:
        LOG.warning(
            "prometheus upstream returned {} — falling back to local shim",
            resp.status_code,
        )
        end_ts = _parse_ts(end, _time.time())
        start_ts = _parse_ts(start, end_ts - 600.0)
        step_s = _parse_ts(step, 15.0)
        local_resp = local_stats.resolve_query_range(
            query or "", start_ts, end_ts, step_s
        )
        return get_prometheus_query_range_response(local_resp, profile)

    return get_prometheus_query_range_response(resp.json(), profile)
