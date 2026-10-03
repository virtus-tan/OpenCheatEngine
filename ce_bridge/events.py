"""Push events for clients that hold a connection open.

The rest of the HTTP API is request/response. opencode asks, the bridge answers,
and in between there is nothing on screen - which is why attaching in Cheat
Engine looked like it had done nothing until a tool happened to be called.

This is the other direction. A client opens GET /api/events once and the bridge
writes to that connection whenever its state changes, so the shell can show a
live connection instead of inferring one from a poll.

Deliberately not a websocket: an event stream is one-directional, survives
proxies, reconnects on its own in every HTTP client, and needs no handshake the
Windows firewall has an opinion about.
"""

import json
import queue
import threading

# A client that stops reading must not be able to stall the bridge, so a
# subscriber's queue is bounded. Overflow drops the oldest event rather than
# blocking the publisher: every event carries the current state, so a dropped
# one costs a moment of staleness and never correctness.
QUEUE_SIZE = 32
HISTORY = 32

HEARTBEAT_SECONDS = 10.0


def frame(kind, data=None, seq=None):
    """One server-sent event.

    Newlines inside the payload would end the frame early, so json.dumps is
    asked not to emit them; a value containing a newline is rare but a broken
    stream is silent and hard to attribute.
    """
    body = json.dumps(data if data is not None else {}, default=str).replace("\n", " ")
    lines = [f"event: {kind}"]
    if seq is not None:
        lines.append(f"id: {seq}")
    lines.append(f"data: {body}")
    return ("\n".join(lines) + "\n\n").encode("utf-8")


KEEPALIVE = b": keepalive\n\n"


class Subscription:
    """One client's end of the stream."""

    def __init__(self, bus):
        self._bus = bus
        self._queue = queue.Queue(QUEUE_SIZE)
        self.closed = False
        self.dropped = 0

    def get(self, timeout):
        """The next event, or None if the timeout passed or this is closed."""
        try:
            return self._queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def close(self):
        if self.closed:
            return
        self.closed = True
        self._bus.unsubscribe(self)


class EventBus:
    def __init__(self, history=HISTORY):
        self._lock = threading.Lock()
        self._subscribers = set()
        self._history = []
        self._history_limit = history
        self._sequence = 0

    def publish(self, kind, data=None):
        with self._lock:
            self._sequence += 1
            event = {"seq": self._sequence, "kind": kind, "data": data or {}}
            self._history.append(event)
            if len(self._history) > self._history_limit:
                del self._history[:-self._history_limit]
            targets = list(self._subscribers)
        for subscription in targets:
            try:
                subscription._queue.put_nowait(event)
            except queue.Full:
                try:
                    subscription._queue.get_nowait()
                    subscription._queue.put_nowait(event)
                    subscription.dropped += 1
                except (queue.Empty, queue.Full):
                    pass
        return event

    def subscribe(self):
        subscription = Subscription(self)
        with self._lock:
            self._subscribers.add(subscription)
        return subscription

    def unsubscribe(self, subscription):
        with self._lock:
            self._subscribers.discard(subscription)

    def count(self):
        with self._lock:
            return len(self._subscribers)

    def peek_sequence(self):
        """The id the next published event will carry.

        The opening frame is written straight to one socket rather than
        published, but it still needs an id so a client can tell whether it
        missed anything.
        """
        with self._lock:
            return self._sequence + 1

    def recent(self, limit=10):
        with self._lock:
            return list(self._history[-limit:])
