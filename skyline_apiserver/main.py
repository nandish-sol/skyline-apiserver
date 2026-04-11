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

from pathlib import Path

from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware

from skyline_apiserver.api.v1 import api_router
from skyline_apiserver.config import CONF, configure
from skyline_apiserver.db import setup as db_setup
from skyline_apiserver.log import LOG, setup as log_setup
from skyline_apiserver.policy import setup as policies_setup
from skyline_apiserver.types import constants

PROJECT_NAME = "Skyline API"


async def on_startup() -> None:
    configure("skyline")
    log_setup(
        Path(CONF.default.log_dir).joinpath(CONF.default.log_file),
        debug=CONF.default.debug,
    )
    policies_setup()
    await db_setup()

    # Set all CORS enabled origins
    if CONF.default.cors_allow_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=[str(origin) for origin in CONF.default.cors_allow_origins],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
    LOG.debug("Skyline API server start")

    # Start notification consumer background thread
    try:
        LOG.info("on_startup: importing notification_consumer...")
        from skyline_apiserver.api.v1.notification_consumer import (
            start_notification_consumer,
        )
        LOG.info("on_startup: starting notification consumer...")
        start_notification_consumer()
        LOG.info("on_startup: notification consumer started successfully")
    except Exception as exc:
        LOG.warning("Failed to start notification consumer: {}", exc)
        LOG.opt(exception=True).debug("notification consumer startup traceback")

    # Start local_stats background sampler (for single-node monitoring without Prometheus)
    try:
        from skyline_apiserver.core import local_stats
        local_stats.start_sampler()
    except Exception as exc:
        LOG.warning("Failed to start local_stats sampler: {}", exc)


async def on_shutdown() -> None:
    LOG.debug("Skyline API server stop")


app = FastAPI(
    title=PROJECT_NAME,
    openapi_url=f"{constants.API_PREFIX}/openapi.json",
    on_startup=[on_startup],
    on_shutdown=[on_shutdown],
)

app.include_router(api_router, prefix=constants.API_PREFIX)

# Always wrap with RBAC middleware — it checks enable_rbac at request time
try:
    from skyline_apiserver.middleware.rbac import RBACMiddleware
    app = RBACMiddleware(app)
except ImportError:
    pass

# License enforcement middleware — outermost wrapper, runs before RBAC
try:
    from skyline_apiserver.middleware.license import LicenseMiddleware
    app = LicenseMiddleware(app)
except ImportError:
    pass
