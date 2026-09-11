"""In-process publish/subscribe bus.

Later phases run fuzzing workers, analysers and schedulers in the same process but
on different threads.  They must not call each other directly.  The event bus is the
only supported channel for announcing that something happened, and it is the same
channel a CLI subscriber will use to stream progress.
"""

from __future__ import annotations

import logging
import threading
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from kmcs.core.exceptions import EventHandlerError

__all__ = ["EventType", "Event", "Subscription", "EventHandler", "EventBus"]

logger = logging.getLogger(__name__)

EventHandler = Callable[["Event"], None]


class EventType(str, Enum):
    """The complete KMCS event vocabulary.

    Events marked *reserved* belong to later phases.  They are declared now so the
    vocabulary lives in exactly one place rather than being scattered as string
    literals across the codebase.
    """

    # --- application lifecycle ------------------------------------------------
    APPLICATION_STARTING = "application.starting"
    APPLICATION_STARTED = "application.started"
    CONFIGURATION_LOADED = "configuration.loaded"
    DATABASE_INITIALIZED = "database.initialized"
    DATABASE_HEALTH_CHECKED = "database.health_checked"

    # --- jobs -----------------------------------------------------------------
    JOB_CREATED = "job.created"
    JOB_STARTED = "job.started"
    JOB_PROGRESS = "job.progress"
    JOB_COMPLETED = "job.completed"
    JOB_FAILED = "job.failed"
    JOB_CANCELLED = "job.cancelled"

    # --- reserved for later phases -------------------------------------------
    TARGET_REGISTERED = "target.registered"
    CAMPAIGN_STARTED = "campaign.started"
    CAMPAIGN_FINISHED = "campaign.finished"
    CRASH_DETECTED = "crash.detected"
    FINDING_CREATED = "finding.created"
    REPORT_GENERATED = "report.generated"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Event(BaseModel):
    """An immutable fact that something happened."""

    model_config = ConfigDict(frozen=True)

    type: EventType
    payload: dict[str, Any] = Field(default_factory=dict)
    id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    timestamp: datetime = Field(default_factory=_utcnow)
    source: str | None = None


@dataclass(frozen=True, slots=True)
class Subscription:
    """A registered handler.  Keep the object to unsubscribe later."""

    id: str
    event_type: EventType | None
    handler: EventHandler


class EventBus:
    """A small, thread-safe, synchronous publish/subscribe bus.

    Delivery is synchronous and ordered by registration.  A failing handler never
    breaks the publisher unless the bus is constructed with
    ``raise_on_handler_error=True`` — fuzzing workers must not die because a GUI
    subscriber had a bug.
    """

    def __init__(self, *, raise_on_handler_error: bool = False) -> None:
        self._lock = threading.RLock()
        self._subscriptions: dict[str, Subscription] = {}
        self._raise_on_handler_error = bool(raise_on_handler_error)

    # ------------------------------------------------------------------ subscribe

    def subscribe(self, event_type: EventType, handler: EventHandler) -> Subscription:
        """Register ``handler`` for one event type."""
        return self._add(event_type, handler)

    def subscribe_all(self, handler: EventHandler) -> Subscription:
        """Register ``handler`` for every event type."""
        return self._add(None, handler)

    def _add(self, event_type: EventType | None, handler: EventHandler) -> Subscription:
        if not callable(handler):
            raise TypeError("event handler must be callable")
        if event_type is not None and not isinstance(event_type, EventType):
            raise TypeError("event_type must be an EventType or None")

        subscription = Subscription(
            id=uuid.uuid4().hex, event_type=event_type, handler=handler
        )
        with self._lock:
            self._subscriptions[subscription.id] = subscription
        return subscription

    def unsubscribe(self, subscription: Subscription | str) -> bool:
        """Remove a subscription.  Returns ``True`` if it existed."""
        subscription_id = (
            subscription.id if isinstance(subscription, Subscription) else subscription
        )
        with self._lock:
            return self._subscriptions.pop(subscription_id, None) is not None

    # ------------------------------------------------------------------ publish

    def publish(self, event: Event) -> int:
        """Deliver ``event`` synchronously.  Returns the number of successes."""
        with self._lock:
            handlers = [
                subscription.handler
                for subscription in self._subscriptions.values()
                if subscription.event_type is None or subscription.event_type == event.type
            ]

        delivered = 0
        for handler in handlers:
            try:
                handler(event)
            except Exception as exc:
                logger.exception(
                    "Event handler %r failed while handling %s",
                    handler,
                    event.type.value,
                )
                if self._raise_on_handler_error:
                    raise EventHandlerError(
                        "Event handler raised an exception",
                        details={
                            "event_type": event.type.value,
                            "handler": getattr(handler, "__qualname__", repr(handler)),
                        },
                    ) from exc
            else:
                delivered += 1
        return delivered

    def emit(
        self,
        event_type: EventType,
        payload: dict[str, Any] | None = None,
        *,
        source: str | None = None,
    ) -> Event:
        """Build and publish an event, returning the published object."""
        event = Event(type=event_type, payload=dict(payload or {}), source=source)
        self.publish(event)
        return event

    # ------------------------------------------------------------------ inspection

    def subscriber_count(self, event_type: EventType | None = None) -> int:
        with self._lock:
            if event_type is None:
                return len(self._subscriptions)
            return sum(
                1
                for subscription in self._subscriptions.values()
                if subscription.event_type is event_type
            )

    def clear(self) -> None:
        """Drop every subscription."""
        with self._lock:
            self._subscriptions.clear()
