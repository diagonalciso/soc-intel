"""
STIX 2.1 Server-Sent Events stream.
Consumers (SIEM, firewall, EDR) subscribe to receive real-time STIX bundles.
"""
import json
import asyncio
from typing import AsyncGenerator

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse

from app.db.redis import get_redis
from app.auth.dependencies import get_current_user
from app.models.user import User

router = APIRouter(prefix="/stream", tags=["stream"])

STREAM_CHANNEL = "socint:stix:stream"


async def _event_generator(request: Request, redis: aioredis.Redis) -> AsyncGenerator[str, None]:
    pubsub = redis.pubsub()
    await pubsub.subscribe(STREAM_CHANNEL)

    try:
        while True:
            if await request.is_disconnected():
                break

            message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
            if message and message["type"] == "message":
                data = message["data"]
                yield f"data: {data}\n\n"
            else:
                # Heartbeat to keep connection alive
                yield ": heartbeat\n\n"
                await asyncio.sleep(5)
    finally:
        await pubsub.unsubscribe(STREAM_CHANNEL)
        await pubsub.close()


@router.get("")
async def stix_stream(
    request: Request,
    redis: aioredis.Redis = Depends(get_redis),
    user: User = Depends(get_current_user),
):
    return StreamingResponse(
        _event_generator(request, redis),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


async def publish_stix_object(redis: aioredis.Redis, stix_obj: dict):
    """Called by connectors/engine to push new objects to all stream consumers."""
    bundle = {
        "type": "bundle",
        "id": f"bundle--{stix_obj['id'].split('--')[1]}",
        "spec_version": "2.1",
        "objects": [stix_obj],
    }
    await redis.publish(STREAM_CHANNEL, json.dumps(bundle))
