"""Live RTSP preview for the Camera tab.

An operator setting up for a capture run needs to know that the camera is
pointed at the driveway and not at the hedge, and that the credentials being
typed into the tab are the ones the camera actually accepts. Both are far
easier to answer from a moving picture than from a probe result, so this widget
shows the stream the camera already serves.

Nothing here changes the camera. It opens the same read-only RTSP stream that
:func:`deauth_correlator.camera.tapo.snapshot` uses, decodes it, and draws it.

Threading contract, which the rest of the GUI also follows: a worker thread
does the decoding and never touches a Tk widget. It posts status lines onto an
unbounded queue and the newest frame into a one-slot queue, and the Tk thread
collects both from an ``after`` timer. A camera that has stopped answering can
therefore block the worker for as long as its timeouts allow without the window
noticing.

OpenCV and Pillow are optional dependencies of this package, so they are
imported only when the operator presses Start; if they are absent the widget
says so and stays inert.

The camera-account credentials are never displayed. Every message is built from
``CameraConfig.rtsp_url(redact=True)``, and anything on its way to the screen is
passed through :func:`_redact_credentials` as a second line of defence.
"""

from __future__ import annotations

import importlib.util
import queue
import re
import socket
import threading
import time
import tkinter as tk
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from tkinter import ttk

from .widgets import PALETTE

#: Frames per second to display. The point of the preview is aim and framing,
#: neither of which improves above this, and every frame not decoded is decoder
#: time the analysis side of the program gets to keep.
DEFAULT_FPS = 12.0

#: How often the Tk thread looks for a new frame. Shorter than the 120 ms the
#: main window uses for its own queue, because at 120 ms the poll interval, not
#: the camera, would decide the frame rate.
POLL_MS = 40

#: Seconds to wait for the RTSP port to accept a TCP connection. This check
#: runs before OpenCV is asked to open anything, because "no route to that
#: address" and "the credentials are wrong" deserve different sentences and
#: FFmpeg reports both as a failure to open.
CONNECT_TIMEOUT_S = 4.0

OPEN_TIMEOUT_MS = 8000
READ_TIMEOUT_MS = 8000

#: Give up if the stream opens but never produces a picture.
FIRST_FRAME_TIMEOUT_S = 12.0
#: Give up if a stream that was working stops producing frames for this long.
STREAM_LOST_S = 6.0
#: Pause between read attempts once reads start failing, so a dead stream is
#: not retried as fast as the loop can issue calls.
RETRY_PAUSE_S = 0.2
#: How often the status line is refreshed with the observed frame rate.
STATS_INTERVAL_S = 2.0

#: A dark surround makes the edges of the picture obvious, which matters when
#: the operator is judging what is inside the camera's field of view.
VIEW_BACKGROUND = "#1f2124"
VIEW_FOREGROUND = "#e8eaed"


@dataclass
class _Frame:
    """One decoded frame on its way from the worker thread to the canvas."""

    session: int
    #: Already scaled to the canvas and converted to RGB, ready for ImageTk.
    image: object
    #: The untouched full-resolution BGR frame, kept so that saving an exhibit
    #: writes what the camera sent rather than what happened to fit on screen.
    original: object
    captured: datetime
    source_size: tuple


class LiveView(ttk.Frame):
    """Start/Stop live RTSP preview with a frame-to-exhibit button.

    ``config`` is a :class:`~deauth_correlator.camera.tapo.CameraConfig`, or a
    callable returning one. The callable form is what the main window uses: the
    address, credentials and stream choice on the Camera tab can all change
    between one Start and the next, and the widget must use the values as they
    are at the moment Start is pressed.

    ``exhibits_dir`` follows the same rule, since the snapshot folder is an
    entry field the operator can edit at any time.
    """

    _TAG_COLOURS = {"error": PALETTE["found"], "ok": PALETTE["not_found"],
                    "muted": PALETTE["muted"]}

    def __init__(self, master, config, exhibits_dir=None,
                 tz_name: str = "America/New_York", fps: float = DEFAULT_FPS,
                 on_saved=None):
        super().__init__(master)
        self._config_source = config
        self._exhibits_source = exhibits_dir
        self.tz_name = tz_name
        self.frame_interval = 1.0 / max(1.0, float(fps))
        self.on_saved = on_saved

        self._events: queue.Queue = queue.Queue()
        self._frames: queue.Queue = queue.Queue(maxsize=1)
        self._stop = threading.Event()
        self._stop.set()
        self._thread: threading.Thread | None = None
        #: Incremented on every start and every stop. A worker that outlived
        #: its Stop keeps posting under its old number and is ignored.
        self._session = 0
        self._closing = False
        self._after_id = None

        self._pil_image = None
        self._imagetk = None
        #: The PhotoImage currently on the canvas. Tk does not own its images,
        #: so dropping this reference lets the garbage collector take the
        #: picture out from under the canvas - the classic Tkinter blank frame.
        self._photo = None
        self._displayed: _Frame | None = None
        #: Sessions whose worker had not returned by the time Stop gave up
        #: waiting. Each still holds an RTSP connection until it reports in.
        self._lingering: set[int] = set()
        self._view_size = (640, 360)
        self._shown = 0
        self._shown_since = 0
        self._stats_at = 0.0

        self._build()
        self._missing = _missing_dependencies()
        if self._missing:
            message = _dependency_message(self._missing)
            self.start_button.configure(state="disabled")
            self._placeholder(message)
            self._status(message, "error")

        self.bind("<Destroy>", self._on_destroy)
        self._after_id = self.after(POLL_MS, self._drain_queue)

    # -- layout ----------------------------------------------------------

    def _build(self) -> None:
        ttk.Label(self, text="Live view",
                  font=("Segoe UI", 11, "bold")).pack(anchor="w")
        ttk.Label(self, foreground=PALETTE["muted"], wraplength=840, justify="left",
                  text="Watch the camera on this computer to confirm it is pointed "
                       "where you think it is before you start capturing. The stream "
                       "is only read, and nothing here is written to the case file "
                       "unless you save a frame.").pack(anchor="w", pady=(2, 8))

        buttons = ttk.Frame(self)
        buttons.pack(anchor="w", pady=(0, 6))
        self.start_button = ttk.Button(buttons, text="Start live view",
                                       command=self.start)
        self.start_button.pack(side="left")
        self.stop_button = ttk.Button(buttons, text="Stop", command=self.stop,
                                      state="disabled")
        self.stop_button.pack(side="left", padx=(8, 0))
        self.save_button = ttk.Button(buttons, text="Save this frame",
                                      command=self.save_frame, state="disabled")
        self.save_button.pack(side="left", padx=(8, 0))

        self.source_var = tk.StringVar(value="No stream open.")
        ttk.Label(self, textvariable=self.source_var, foreground=PALETTE["muted"]).pack(
            anchor="w", pady=(0, 6))

        self.canvas = tk.Canvas(self, height=360, background=VIEW_BACKGROUND,
                                highlightthickness=1,
                                highlightbackground=PALETTE["muted"])
        self.canvas.pack(fill="both", expand=True)
        self._image_item = self.canvas.create_image(320, 180, anchor="center")
        self._text_item = self.canvas.create_text(
            320, 180, anchor="center", fill=VIEW_FOREGROUND, width=520,
            justify="center", font=("Segoe UI", 10),
            text="Not streaming. Enter the camera address and camera-account "
                 "credentials above, then press 'Start live view'.")
        self.canvas.bind("<Configure>", self._on_resize)

        self.status_var = tk.StringVar(value="Not streaming.")
        self.status_label = ttk.Label(self, textvariable=self.status_var,
                                      foreground=PALETTE["muted"], wraplength=840,
                                      justify="left")
        self.status_label.pack(anchor="w", pady=(6, 0))

    def _on_resize(self, event) -> None:
        centre = (event.width // 2, event.height // 2)
        self.canvas.coords(self._image_item, *centre)
        self.canvas.coords(self._text_item, *centre)
        # The worker scales each frame to fit, so it needs the current size. A
        # plain attribute is enough: the worker only ever reads it, and reading
        # a size one resize out of date costs a single mis-sized frame.
        self._view_size = (max(event.width - 2, 160), max(event.height - 2, 120))

    # -- lifecycle -------------------------------------------------------

    def is_streaming(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def start(self) -> None:
        """Open the stream on a worker thread. Pressing Start twice is harmless."""
        if self.is_streaming():
            return
        if self._missing:
            self._status(_dependency_message(self._missing), "error")
            return

        try:
            from PIL import Image, ImageTk
        except ImportError as exc:
            # Pillow can be installed without its Tkinter binding, and that only
            # shows up on the ImageTk import - "import PIL" succeeds either way.
            self._status(f"Pillow is installed but PIL.ImageTk is not usable "
                         f"({exc}). Live view needs a Pillow build with Tkinter "
                         f"support; the rest of the camera features still work.",
                         "error")
            return
        self._pil_image = Image
        self._imagetk = ImageTk

        config = self._resolve_config()
        if config is None or not config.host:
            self._status("Enter the camera's IP address first.", "error")
            return

        self._session += 1
        session = self._session
        # A fresh event per session: a worker abandoned by an earlier Stop must
        # keep seeing its own event set, whatever the new session does.
        self._stop = threading.Event()
        self._shown = 0
        self._shown_since = 0
        self._stats_at = time.monotonic()

        # Drop the previous session's picture before this one opens. Stop leaves
        # the last frame on the canvas on purpose, so it can still be saved; but
        # Start invalidates it, and carrying it over is how the wrong camera ends
        # up in the exhibits folder. Retype the address for a second camera, let
        # this session fail to connect, and a retained frame would sit there with
        # Save still armed - the operator would be looking at the first camera's
        # driveway under an error message naming the second, and the saved
        # exhibit would carry the new camera's name and the old one's picture.
        self._displayed = None
        self._photo = None
        self.canvas.itemconfigure(self._image_item, image="")
        self.save_button.configure(state="disabled")

        redacted = config.rtsp_url(redact=True)
        self.source_var.set(f"Source: {redacted}")
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self._placeholder(f"Connecting to {config.host} …")
        self._status("Connecting …", "muted")

        self._thread = threading.Thread(
            target=self._run, args=(config, session, self._stop),
            name=f"liveview-{session}", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 1.5) -> None:
        """Close the stream. Call this from the Tk thread only.

        The last frame is deliberately left on the canvas so it can still be
        saved as an exhibit after the operator has stopped the stream.
        """
        self._stop.set()
        thread, self._thread = self._thread, None
        stopped = self._session
        # Everything the old worker has not posted yet belongs to a session
        # that is over, and is discarded on arrival.
        self._session += 1

        lingering = False
        if thread and thread.is_alive():
            thread.join(timeout=timeout)
            lingering = thread.is_alive()
        if lingering:
            # Keep the handle. A worker that has not returned is still inside
            # cv2.VideoCapture holding an RTSP session open, and reporting
            # is_streaming() as False while that is true makes start()'s
            # "pressing Start twice is harmless" guard useless: every Stop/Start
            # cycle would stack another thread and another connection on a
            # camera that serves only two or three. _handle("finished") clears
            # it when the decoder finally returns.
            self._thread = thread
            self._lingering.add(stopped)

        if self._closing:
            return
        self.start_button.configure(
            state="disabled" if (lingering or self._missing) else "normal")
        self.stop_button.configure(state="disabled")
        if self._missing:
            # Never overwrite the install instructions with "Stopped." - that
            # would leave the operator with a dead button and no explanation.
            self._status(_dependency_message(self._missing), "error")
        elif lingering:
            # The worker is a daemon holding the only reference to the capture,
            # and its finally clause releases it. Waiting longer here would
            # freeze the window for exactly as long as the camera is hanging.
            self._status("Stopping. The decoder has not returned yet; the "
                         "connection is released as soon as it does. Start is "
                         "enabled again the moment it does.", "muted")
        elif self._displayed is not None:
            self._status("Stopped. The last frame is still on screen and can "
                         "be saved.", "muted")
        else:
            self._status("Stopped.", "muted")

    def _on_destroy(self, event) -> None:
        # Child widgets raise <Destroy> as well; only this frame's own teardown
        # means the widget is going away.
        if event.widget is not self or self._closing:
            return
        self._closing = True
        if self._after_id is not None:
            self.after_cancel(self._after_id)
            self._after_id = None
        self.stop(timeout=1.5)

    # -- worker ----------------------------------------------------------

    def _run(self, config, session: int, stop: threading.Event) -> None:
        """Worker thread: open the stream, publish frames, always release."""

        def say(text: str, tag: str = "muted") -> None:
            self._events.put(
                ("status", (session, _redact_credentials(text), tag)))

        try:
            import cv2
        except ImportError as exc:
            say(f"OpenCV would not import ({exc}). Install it with "
                f"'pip install opencv-python'.", "error")
            self._events.put(("finished", session))
            return

        capture = None
        try:
            redacted = config.rtsp_url(redact=True)
            unreachable = _reach_rtsp(config.host, int(config.rtsp_port))
            if unreachable:
                say(unreachable, "error")
                return

            capture = _open_capture(cv2, config.rtsp_url())
            if not capture.isOpened():
                say(f"The RTSP port is open but the stream would not start. That "
                    f"is almost always a wrong camera-account username or password "
                    f"(the Camera Account from the Tapo app, not the TP-Link cloud "
                    f"login), or a stream this camera does not serve. Tried "
                    f"{redacted}.", "error")
                return

            self._pump(cv2, capture, session, stop, say, redacted)
        except Exception as exc:
            # Whatever the decoder did, the operator gets a sentence in the
            # status line rather than a traceback in a console they may not
            # have open.
            say(f"Live view failed: {exc.__class__.__name__}: {exc}", "error")
        finally:
            if capture is not None:
                # Only the thread that owns the capture may release it.
                # Releasing from the Tk thread while a read is in flight can
                # take the FFmpeg backend down with it.
                capture.release()
            self._events.put(("finished", session))

    def _pump(self, cv2, capture, session: int, stop: threading.Event,
              say, redacted: str) -> None:
        """Read the stream until stopped, publishing at the display rate."""
        opened_at = time.monotonic()
        last_shown = 0.0
        # One clock, timing the last frame actually put on screen. Timing failed
        # grabs instead leaves a hole: a stream whose grab() keeps succeeding
        # while retrieve() returns nothing never sets that clock, so the picture
        # freezes with the status still reading "Live." - the precise false
        # reassurance this widget exists to prevent.
        last_published = opened_at
        seen = 0

        while not stop.is_set():
            if seen == 0 and time.monotonic() - opened_at >= FIRST_FRAME_TIMEOUT_S:
                say(f"The stream at {redacted} opened but sent no frames within "
                    f"{FIRST_FRAME_TIMEOUT_S:.0f} s. Try the 'sd' stream, and check "
                    f"that the camera is not already serving as many RTSP clients "
                    f"as it allows.", "error")
                return
            if seen and time.monotonic() - last_published >= STREAM_LOST_S:
                say("The camera stopped sending frames. It may have been "
                    "power-cycled, or another client may have taken the "
                    "stream. Press 'Start live view' to reconnect.", "error")
                return

            # Grab every frame the camera sends but decode only at the display
            # rate. Reading slower than the stream arrives makes the decoder's
            # buffer grow, and the preview then falls further behind real time
            # the longer it is left running.
            if not capture.grab():
                stop.wait(RETRY_PAUSE_S)
                continue

            now = time.monotonic()
            if now - last_shown < self.frame_interval:
                continue

            ok, frame = capture.retrieve()
            if not ok or frame is None:
                continue
            last_shown = now
            last_published = now
            seen += 1
            self._publish(cv2, frame, session)

    def _publish(self, cv2, frame, session: int) -> None:
        width, height = self._view_size
        rgb = cv2.cvtColor(_fit(cv2, frame, width, height), cv2.COLOR_BGR2RGB)
        item = _Frame(session=session, image=self._pil_image.fromarray(rgb),
                      original=frame, captured=datetime.now(tz=timezone.utc),
                      source_size=(frame.shape[1], frame.shape[0]))

        # Replace rather than queue. If the Tk thread is behind, the newest
        # frame is the only one worth drawing, and a backlog would show the
        # operator a picture that is progressively older than the driveway.
        try:
            self._frames.get_nowait()
        except queue.Empty:
            pass
        try:
            self._frames.put_nowait(item)
        except queue.Full:
            pass

    # -- Tk thread -------------------------------------------------------

    def _drain_queue(self) -> None:
        self._after_id = None
        if self._closing or not self.winfo_exists():
            return
        try:
            while True:
                kind, payload = self._events.get_nowait()
                self._handle(kind, payload)
        except queue.Empty:
            pass
        self._show_latest_frame()
        self._after_id = self.after(POLL_MS, self._drain_queue)

    def _handle(self, kind: str, payload) -> None:
        if kind == "status":
            session, text, tag = payload
            if session == self._session:
                self._status(text, tag)
                if tag == "error":
                    self._placeholder(text)
        elif kind == "finished":
            self._lingering.discard(payload)
            if payload != self._session:
                # An abandoned worker reporting in. Everything else it posted is
                # discarded, but this one event matters: it is the only signal
                # that the RTSP session it was still holding has been released.
                # Identify it by thread name rather than by liveness - it posts
                # this from inside its own finally clause, so it is very often
                # still alive at the moment the event is handled.
                mine = (self._thread is not None
                        and self._thread.name == f"liveview-{payload}")
                if mine and not self._lingering and not self._closing:
                    self._thread = None
                    self.start_button.configure(
                        state="disabled" if self._missing else "normal")
                    if not self._missing:
                        self._status("The previous connection has been "
                                     "released. Ready.", "muted")
                return
            self._thread = None
            self._stop.set()
            self.start_button.configure(
                state="disabled" if self._missing else "normal")
            self.stop_button.configure(state="disabled")

    def _show_latest_frame(self) -> None:
        frame = None
        while True:  # take the newest and discard anything older
            try:
                frame = self._frames.get_nowait()
            except queue.Empty:
                break
        if frame is None or frame.session != self._session:
            return

        try:
            photo = self._imagetk.PhotoImage(frame.image)
        except Exception as exc:
            self._status(f"Could not draw the frame: {exc}", "error")
            return

        self.canvas.itemconfigure(self._image_item, image=photo)
        # Hold the reference. Tk keeps only a name for the image, so without
        # this attribute the PhotoImage is collected the moment this method
        # returns and the canvas goes blank.
        self._photo = photo
        self._displayed = frame
        self.canvas.itemconfigure(self._text_item, text="")
        self.save_button.configure(state="normal")

        if self._shown == 0:
            self._status("Live.", "ok")
        self._shown += 1
        self._shown_since += 1

        elapsed = time.monotonic() - self._stats_at
        if elapsed >= STATS_INTERVAL_S:
            width, height = frame.source_size
            self._status(f"Live: {width}x{height} at "
                         f"{self._shown_since / elapsed:.1f} frames/s displayed.",
                         "ok")
            self._stats_at = time.monotonic()
            self._shown_since = 0

    def save_frame(self) -> None:
        """Write the frame now on screen into the exhibits folder as a JPEG."""
        frame = self._displayed
        if frame is None:
            self._status("There is no frame on screen to save yet.", "error")
            return
        try:
            import cv2
        except ImportError:
            self._status("Saving a frame needs OpenCV: pip install opencv-python.",
                         "error")
            return

        directory = Path(self._resolve_exhibits() or "exhibits")
        target = _exhibit_path(directory, _to_local(frame.captured, self.tz_name))
        try:
            directory.mkdir(parents=True, exist_ok=True)
            ok, buffer = cv2.imencode(".jpg", frame.original)
            if not ok:
                raise RuntimeError("OpenCV could not encode the frame as a JPEG")
            # Encoded here and written through pathlib rather than handed to
            # cv2.imwrite, because imwrite opens the path through the C locale
            # and returns False without an error for a Windows path containing
            # characters outside it. An exhibit must not go missing because a
            # case number has an accent in it.
            target.write_bytes(buffer.tobytes())
        except Exception as exc:
            self._status(f"Could not save the frame: {exc}", "error")
            return

        self._status(f"Saved {target}", "ok")
        if self.on_saved:
            try:
                self.on_saved(target)
            except Exception:
                pass

    # -- small helpers ---------------------------------------------------

    def _resolve_config(self):
        return (self._config_source() if callable(self._config_source)
                else self._config_source)

    def _resolve_exhibits(self):
        return (self._exhibits_source() if callable(self._exhibits_source)
                else self._exhibits_source)

    def _status(self, text: str, tag: str = "muted") -> None:
        if self._closing:
            return
        self.status_var.set(text)
        self.status_label.configure(
            foreground=self._TAG_COLOURS.get(tag, PALETTE["muted"]))

    def _placeholder(self, text: str) -> None:
        """Put a message in the middle of the viewport, over the last picture."""
        if self._closing:
            return
        self.canvas.itemconfigure(self._text_item, text=text)


def _fit(cv2, frame, width: int, height: int):
    """Scale a frame to fit ``width`` x ``height`` without distorting it."""
    source_height, source_width = frame.shape[:2]
    if not source_width or not source_height:
        return frame
    scale = min(width / source_width, height / source_height)
    target = (max(int(source_width * scale), 1), max(int(source_height * scale), 1))
    if target == (source_width, source_height):
        return frame
    # INTER_AREA is the correct filter for shrinking and a poor one for
    # enlarging, which is the usual mistake when a 360p stream fills a big pane.
    interpolation = cv2.INTER_AREA if scale < 1 else cv2.INTER_LINEAR
    return cv2.resize(frame, target, interpolation=interpolation)


def _open_capture(cv2, url: str):
    """Open an RTSP capture with connect and read timeouts where available.

    Without them FFmpeg waits on its own defaults, which are long enough that a
    Stop press would sit through one before the thread could be joined and the
    socket closed.
    """
    open_timeout = getattr(cv2, "CAP_PROP_OPEN_TIMEOUT_MSEC", None)
    read_timeout = getattr(cv2, "CAP_PROP_READ_TIMEOUT_MSEC", None)
    if open_timeout is not None and read_timeout is not None:
        try:
            return cv2.VideoCapture(url, cv2.CAP_FFMPEG,
                                    [int(open_timeout), OPEN_TIMEOUT_MS,
                                     int(read_timeout), READ_TIMEOUT_MS])
        except Exception:
            pass  # builds older than the parameter-list form reject it outright
    return cv2.VideoCapture(url, cv2.CAP_FFMPEG)


def _reach_rtsp(host: str, port: int) -> str:
    """Return why the RTSP port cannot be reached, or an empty string if it can."""
    if not host:
        return "No camera address has been entered."
    try:
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT_S):
            return ""
    except socket.gaierror:
        return (f"'{host}' could not be resolved. Use the camera's IP address "
                f"unless its name is in DNS.")
    except ConnectionRefusedError:
        return (f"{host}:{port} refused the connection. RTSP is either turned off "
                f"on the camera or the port number is wrong - the Tapo C100 uses "
                f"554.")
    except TimeoutError:
        return (f"No answer from {host}:{port} within {CONNECT_TIMEOUT_S:.0f} s. "
                f"Check that the camera is powered on, that the address is right, "
                f"and that this computer can reach that network.")
    except OSError as exc:
        return f"Could not reach {host}:{port}: {exc}"


def _exhibit_path(directory: Path, local: datetime) -> Path:
    """``liveview_YYYYmmdd_HHMMSS.jpg``, matching the motion recorder's naming.

    A counter is appended when two frames are saved inside the same second, so
    that one exhibit can never quietly overwrite another.
    """
    stamp = local.strftime("%Y%m%d_%H%M%S")
    target = directory / f"liveview_{stamp}.jpg"
    counter = 2
    while target.exists():
        target = directory / f"liveview_{stamp}_{counter}.jpg"
        counter += 1
    return target


def _to_local(utc: datetime, tz_name: str):
    from zoneinfo import ZoneInfo
    try:
        return utc.astimezone(ZoneInfo(tz_name))
    except Exception:
        return utc


#: Credentials as they appear in an RTSP URL: everything between the scheme and
#: the "@" that separates userinfo from the host. Greedy up to the *last* "@",
#: because a password may itself contain one and the userinfo ends at the last;
#: stopping at the first would leave the tail of such a password on screen. The
#: class excludes "/" and whitespace, so the match cannot run past the host into
#: the stream path or into a later sentence.
_RTSP_CREDENTIALS = re.compile(r"(rtsp://)[^/\s]*@", re.IGNORECASE)


def _redact_credentials(text: str) -> str:
    """Strip camera credentials out of anything heading for the screen.

    Messages are built from redacted URLs already. This is the belt over those
    braces, because an exception raised deeper down can carry the URL that was
    handed to OpenCV, credentials and all.

    It rewrites the whole userinfo of any RTSP URL rather than searching for the
    password as a substring. Searching for the substring was the obvious
    implementation and it is the wrong one twice over. It corrupts the message:
    a password of "554" turns the port into "<password>", a password of "camera"
    edits the prose, and a password of "pass" rewrites the "pass" inside the
    "<password>" placeholder it has just inserted, producing
    "<<<password>word>word>". And it is too narrow: it hides the password but
    leaves the camera account's username in clear text, so a screenshot that
    reaches a case file still names the account. Replacing the userinfo
    wholesale has neither problem, cannot cascade because re.sub does not
    rescan what it has substituted, and works even on a URL this function was
    never told the credentials for.

    The limit is worth stating: credentials only reach these messages inside a
    URL, which is what this covers. It is not a general secret filter.
    """
    return _RTSP_CREDENTIALS.sub(r"\1<user>:<password>@", text)


def _missing_dependencies() -> list[str]:
    """Names of the packages live view needs and cannot find.

    ``find_spec`` answers without importing either package, which keeps the
    cost of building the Camera tab the same whether or not they are installed.
    """
    missing = []
    for module, package in (("cv2", "opencv-python"), ("PIL", "Pillow")):
        try:
            if importlib.util.find_spec(module) is None:
                missing.append(package)
        except (ImportError, ValueError):
            missing.append(package)
    return missing


def _dependency_message(missing: list[str]) -> str:
    return (f"Live view needs {' and '.join(missing)}, which "
            f"{'is' if len(missing) == 1 else 'are'} not installed. Install "
            f"{'it' if len(missing) == 1 else 'them'} with: pip install "
            f"{' '.join(missing)}. Everything else on this tab works without "
            f"{'it' if len(missing) == 1 else 'them'}.")
