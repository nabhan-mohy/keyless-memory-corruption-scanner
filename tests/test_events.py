"""Event bus behaviour."""

from __future__ import annotations

import pytest

from kmcs.core.events import Event, EventBus, EventType
from kmcs.core.exceptions import EventHandlerError


def test_publish_reaches_matching_subscriber() -> None:
    bus = EventBus()
    received: list[Event] = []
    bus.subscribe(EventType.CRASH_DETECTED, received.append)

    delivered = bus.publish(Event(type=EventType.CRASH_DETECTED, payload={"x": 1}))

    assert delivered == 1
    assert len(received) == 1
    assert received[0].payload == {"x": 1}


def test_publish_skips_non_matching_subscriber() -> None:
    bus = EventBus()
    received: list[Event] = []
    bus.subscribe(EventType.CRASH_DETECTED, received.append)

    bus.publish(Event(type=EventType.JOB_CREATED))

    assert received == []


def test_wildcard_subscriber_receives_everything() -> None:
    bus = EventBus()
    received: list[Event] = []
    bus.subscribe_all(received.append)

    bus.emit(EventType.JOB_CREATED)
    bus.emit(EventType.JOB_STARTED)

    assert [event.type for event in received] == [
        EventType.JOB_CREATED,
        EventType.JOB_STARTED,
    ]


def test_unsubscribe_stops_delivery() -> None:
    bus = EventBus()
    received: list[Event] = []
    subscription = bus.subscribe_all(received.append)

    assert bus.unsubscribe(subscription) is True
    assert bus.unsubscribe(subscription) is False

    bus.emit(EventType.JOB_CREATED)
    assert received == []


def test_emit_builds_a_well_formed_event() -> None:
    bus = EventBus()
    event = bus.emit(EventType.APPLICATION_STARTED, {"version": "0.1.0"}, source="test")

    assert isinstance(event, Event)
    assert event.type is EventType.APPLICATION_STARTED
    assert event.payload == {"version": "0.1.0"}
    assert event.source == "test"
    assert event.id
    assert event.timestamp.tzinfo is not None


def test_failing_handler_is_isolated_by_default() -> None:
    bus = EventBus()
    seen: list[Event] = []

    def boom(_event: Event) -> None:
        raise RuntimeError("handler exploded")

    bus.subscribe_all(boom)
    bus.subscribe_all(seen.append)

    delivered = bus.publish(Event(type=EventType.JOB_CREATED))

    assert delivered == 1
    assert len(seen) == 1


def test_failing_handler_raises_in_strict_mode() -> None:
    bus = EventBus(raise_on_handler_error=True)

    def boom(_event: Event) -> None:
        raise RuntimeError("handler exploded")

    bus.subscribe_all(boom)

    with pytest.raises(EventHandlerError):
        bus.publish(Event(type=EventType.JOB_CREATED))


def test_subscriber_count() -> None:
    bus = EventBus()
    bus.subscribe(EventType.JOB_CREATED, lambda event: None)
    bus.subscribe_all(lambda event: None)

    assert bus.subscriber_count() == 2
    assert bus.subscriber_count(EventType.JOB_CREATED) == 1
    assert bus.subscriber_count(EventType.JOB_STARTED) == 0


def test_clear_drops_all_subscriptions() -> None:
    bus = EventBus()
    bus.subscribe_all(lambda event: None)
    bus.clear()
    assert bus.subscriber_count() == 0


def test_non_callable_handler_is_rejected() -> None:
    bus = EventBus()
    with pytest.raises(TypeError):
        bus.subscribe(EventType.JOB_CREATED, "not-callable")  # type: ignore[arg-type]
