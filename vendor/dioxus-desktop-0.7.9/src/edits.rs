//! The internal edit queue facilitating native <-> webview communication.
//!
//! Originally, we used long-polling on the wry custom protocol to send edits to the webview.
//! Due to bugs in wry on android, we switched to a websocket connection that the webview connects to.
//! We use the sledgehammer crate to build batches of edits and send them through the websocket to
//! the webview.
//!
//! Using a websocket lets us send binary data to the webview quite efficiently and does encounter
//! many of the issues with regular request/response protocols. Note that the websocket max frame
//! size is quite large (9.22 exabytes), so we can have very large batches without issue.
//!
//! Using websockets does mean we need to handle security and content security policies ourselves.
//! The code here generates a random key that the webview must use to connect to the websocket.
//! We use the initialization script API to setup the websocket connection without leaking the key
//! to the webview itself in case there's untrusted content in the webview.
//!
//! Some operating systems (like iOS) will kill the websocket connection when the device goes to sleep.
//! If this happens, we will automatically switch to a new port and notify the webview of the new location
//! and key. The webview will then reconnect to the new port and continue receiving edits.

use dioxus_interpreter_js::MutationState;
use futures_channel::oneshot;
use futures_util::FutureExt;
use rand::{RngCore, SeedableRng};
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::{
    net::IpAddr,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};
use tokio::sync::Notify;

/// This handles communication between the requests that the webview makes and the interpreter.
#[derive(Clone)]
pub(crate) struct WryQueue {
    inner: Rc<RefCell<WryQueueInner>>,
}

impl WryQueue {
    pub(crate) fn with_mutation_state_mut<O: 'static>(
        &self,
        callback: impl FnOnce(&mut MutationState) -> O,
    ) -> O {
        let mut inner = self.inner.borrow_mut();
        callback(&mut inner.mutation_state)
    }

    /// Send a list of mutations to the webview
    pub(crate) fn send_edits(&self) {
        let mut myself = self.inner.borrow_mut();
        let webview_id = myself.location.webview_id;
        let serialized_edits = myself.mutation_state.export_memory();
        let receiver = myself.websocket.send_edits(webview_id, serialized_edits);
        myself.edits_in_progress = Some(receiver);
    }

    /// Wait until all pending edits have been rendered in the webview
    pub(crate) fn poll_edits_flushed(
        &self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<()> {
        let mut self_mut = self.inner.borrow_mut();
        if let Some(receiver) = self_mut.edits_in_progress.as_mut() {
            match receiver.poll_unpin(cx) {
                std::task::Poll::Ready(Ok(())) => {
                    self_mut.edits_in_progress = None;
                    std::task::Poll::Ready(())
                }
                std::task::Poll::Ready(Err(_)) => {
                    panic!("An edit acknowledgement was cancelled before the webview confirmed it")
                }
                std::task::Poll::Pending => std::task::Poll::Pending,
            }
        } else {
            std::task::Poll::Ready(())
        }
    }

    /// Check if there is a new location for the websocket edits server.
    pub(crate) fn poll_new_edits_location(
        &self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<()> {
        let mut self_mut = self.inner.borrow_mut();
        let poll = self_mut
            .server_location_changed_future
            .as_mut()
            .poll_unpin(cx);
        if poll.is_ready() {
            // If the future is ready, we need to reset it to wait for the next change
            self_mut.server_location_changed_future =
                owned_notify_future(self_mut.server_location_changed.clone());
        }
        poll
    }

    /// Get the websocket path that the webview should connect to in order to receive edits
    pub(crate) fn edits_path(&self) -> String {
        let WebviewWebsocketLocation {
            webview_id, server, ..
        } = &self.inner.borrow().location;
        let server = server.lock().unwrap();
        let port = server.port;
        let key = &server.client_key;
        let key_hex = encode_key_string(key);
        format!("ws://127.0.0.1:{port}/{webview_id}/{key_hex}")
    }

    /// Get the key the client should expect from the server when connecting to the websocket.
    pub(crate) fn required_server_key(&self) -> String {
        let server = &self.inner.borrow().location.server;
        let server = server.lock().unwrap();
        encode_key_string(&server.server_key)
    }
}

pub(crate) struct WryQueueInner {
    location: WebviewWebsocketLocation,
    websocket: EditWebsocket,
    // If this webview is currently waiting for an edit to be flushed. We don't run the virtual dom while this is true to avoid running effects before the dom has been updated
    edits_in_progress: Option<oneshot::Receiver<()>>,
    // The socket may be killed by the OS while running. If it does, this channel will receive the new server location
    server_location_changed: Arc<Notify>,
    server_location_changed_future: Pin<Box<dyn Future<Output = ()>>>,
    mutation_state: MutationState,
}

/// The location of a webview websocket connection. This is used to identify the webview and the port it is connected to.
#[derive(Clone)]
pub(crate) struct WebviewWebsocketLocation {
    /// The id of the webview that this websocket is connected to
    webview_id: u32,
    server: Arc<Mutex<ServerLocation>>,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct ServerLocation {
    /// The listener/key generation. A connection may only activate this exact generation.
    generation: u64,
    /// The port the websocket is on
    port: u16,
    /// A key that every websocket connection that originates from this application will use to identify itself.
    /// We use this to make sure no external applications can connect to our websocket and receive UI updates.
    client_key: [u8; KEY_SIZE],
    /// The key that the server must respond with for the client to connect to the websocket
    server_key: [u8; KEY_SIZE],
}

/// Start a new server on an available port on localhost. Return the server location and the TCP listener that is bound to the port.
pub(crate) fn start_server(generation: u64) -> (ServerLocation, TcpListener) {
    let client_key = create_secure_key();
    let server_key = create_secure_key();
    let server = TcpListener::bind((IpAddr::from([127, 0, 0, 1]), 0))
        .expect("Failed to bind local TCP listener for edit socket");
    let port = server.local_addr().unwrap().port();
    let location = ServerLocation {
        generation,
        port,
        client_key,
        server_key,
    };
    (location, server)
}

/// The websocket listener that the webview will connect to in order to receive edits and send requests. There
/// is only one websocket listener per application even if there are multiple windows so we don't use all the
/// open ports.
#[derive(Clone)]
pub(crate) struct EditWebsocket {
    current_location: Arc<Mutex<ServerLocation>>,
    max_webview_id: Arc<AtomicU32>,
    connections: Arc<RwLock<HashMap<u32, WebviewConnectionState>>>,
    server_location: Arc<Notify>,
}

const DEFAULT_HANDSHAKE_LIMIT: usize = 8;
const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Clone)]
struct HandshakeConfig {
    limit: usize,
    timeout: Duration,
}

struct HandshakeSlots {
    in_use: AtomicUsize,
    limit: usize,
}

impl HandshakeSlots {
    fn new(limit: usize) -> Self {
        assert!(limit > 0, "The WebSocket handshake limit must be positive");
        Self {
            in_use: AtomicUsize::new(0),
            limit,
        }
    }

    fn try_acquire(self: &Arc<Self>) -> Option<HandshakeSlot> {
        let mut current = self.in_use.load(Ordering::Acquire);
        loop {
            if current >= self.limit {
                return None;
            }
            match self.in_use.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(HandshakeSlot(self.clone())),
                Err(observed) => current = observed,
            }
        }
    }
}

struct HandshakeSlot(Arc<HandshakeSlots>);

impl Drop for HandshakeSlot {
    fn drop(&mut self) {
        self.0.in_use.fetch_sub(1, Ordering::Release);
    }
}

/// A TCP stream whose read and write timeouts share one handshake deadline.
struct HandshakeStream {
    stream: TcpStream,
    deadline: Option<Instant>,
}

impl HandshakeStream {
    fn new(stream: TcpStream, timeout: Duration) -> Self {
        Self {
            stream,
            deadline: Some(
                Instant::now()
                    .checked_add(timeout)
                    .expect("WebSocket handshake deadline overflowed"),
            ),
        }
    }

    fn apply_deadline(&self) -> io::Result<()> {
        let Some(deadline) = self.deadline else {
            return Ok(());
        };
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::TimedOut, "WebSocket handshake timed out")
            })?;
        self.stream.set_read_timeout(Some(remaining))?;
        self.stream.set_write_timeout(Some(remaining))
    }

    fn finish_handshake(&mut self) -> io::Result<()> {
        self.deadline = None;
        self.stream.set_read_timeout(None)?;
        self.stream.set_write_timeout(None)
    }
}

impl Read for HandshakeStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.apply_deadline()?;
        self.stream.read(buffer)
    }
}

impl Write for HandshakeStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.apply_deadline()?;
        self.stream.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.apply_deadline()?;
        self.stream.flush()
    }
}

impl EditWebsocket {
    pub(crate) fn start() -> Self {
        Self::start_with_handshake_config(HandshakeConfig {
            limit: DEFAULT_HANDSHAKE_LIMIT,
            timeout: DEFAULT_HANDSHAKE_TIMEOUT,
        })
    }

    #[cfg(test)]
    fn start_with_handshake_config_for_test(
        limit: usize,
        timeout: Duration,
    ) -> (Self, Arc<HandshakeSlots>) {
        Self::start_with_handshake_config_and_slots(HandshakeConfig { limit, timeout })
    }

    fn start_with_handshake_config(handshake: HandshakeConfig) -> Self {
        Self::start_with_handshake_config_and_slots(handshake).0
    }

    fn start_with_handshake_config_and_slots(
        handshake: HandshakeConfig,
    ) -> (Self, Arc<HandshakeSlots>) {
        let connections = Arc::new(RwLock::new(HashMap::new()));

        let notify = Arc::new(Notify::new());
        let (location, server) = start_server(0);
        let current_location = Arc::new(Mutex::new(location));
        let handshakes = Arc::new(HandshakeSlots::new(handshake.limit));

        let connections_ = connections.clone();
        let current_location_ = current_location.clone();
        let notify_ = notify.clone();
        let handshakes_ = handshakes.clone();
        std::thread::spawn(move || {
            Self::accept_loop(
                notify_,
                server,
                location,
                current_location_,
                connections_,
                handshakes_,
                handshake,
            )
        });

        (
            Self {
                connections,
                max_webview_id: Default::default(),
                current_location,
                server_location: notify,
            },
            handshakes,
        )
    }

    /// Accepts incoming websocket connections and handles them in a loop.
    ///
    /// New sockets are accepted and then put in to a new thread to handle the connection.
    /// This is implemented using traditional sync code to allow us to be independent of the async runtime.
    fn accept_loop(
        notify: Arc<Notify>,
        mut server: TcpListener,
        mut listener_location: ServerLocation,
        current_location: Arc<Mutex<ServerLocation>>,
        connections: Arc<RwLock<HashMap<u32, WebviewConnectionState>>>,
        handshakes: Arc<HandshakeSlots>,
        handshake: HandshakeConfig,
    ) {
        loop {
            // Accept connections until we hit an error
            while let Ok((stream, _)) = server.accept() {
                let Some(slot) = handshakes.try_acquire() else {
                    let _ = stream.shutdown(Shutdown::Both);
                    continue;
                };
                let current_location = current_location.clone();
                let connections = connections.clone();
                let timeout = handshake.timeout;
                let accepted_location = listener_location;
                std::thread::spawn(move || {
                    Self::handle_connection_for_location(
                        stream,
                        current_location,
                        connections,
                        timeout,
                        slot,
                        accepted_location,
                    );
                });
            }

            // Switch ports and reconnect on a different port if the server is killed by the OS. This
            // will happen if an IOS device goes to sleep
            //
            // For security, it is important that the keys are also regenerated when the server is restarted.
            // The client may try to reconnect to the old port that is now being used by an attacker who steals the client
            // key and uses it to read the edits from the new port.
            let next_generation = current_location
                .lock()
                .unwrap()
                .generation
                .checked_add(1)
                .expect("WebSocket listener generation exhausted");
            let (location, new_server) = start_server(next_generation);
            *current_location.lock().unwrap() = location;
            notify.notify_waiters();
            server = new_server;
            listener_location = location;
        }
    }

    fn handle_connection_for_location(
        stream: TcpStream,
        server_location: Arc<Mutex<ServerLocation>>,
        connections: Arc<RwLock<HashMap<u32, WebviewConnectionState>>>,
        handshake_timeout: Duration,
        _slot: HandshakeSlot,
        current_server_location: ServerLocation,
    ) {
        use tungstenite::handshake::server::{Request, Response};

        let hex_encoded_client_key = encode_key_string(&current_server_location.client_key);
        let hex_encoded_server_key = encode_key_string(&current_server_location.server_key);
        let mut location = None;

        #[allow(clippy::result_large_err)]
        let on_request = |req: &Request, res| {
            // Try to parse the webview id and key from the path
            let path = req.uri().path();

            // The path should have two parts `/webview_id/key`
            let mut segments = path.trim_matches('/').split('/');
            let webview_id = segments
                .next()
                .and_then(|s| s.parse::<u32>().ok())
                .ok_or_else(|| {
                    Response::builder()
                        .status(400)
                        .body(Some("Bad Request: Invalid webview ID".to_string()))
                        .unwrap()
                })?;
            let key = segments.next().ok_or_else(|| {
                Response::builder()
                    .status(400)
                    .body(Some("Bad Request: Missing key".to_string()))
                    .unwrap()
            })?;

            // Make sure the key matches the expected key.
            // VERY IMPORTANT: We cannot use normal string comparison here because it reveals information
            // about the key based on timing information. Instead we use a constant time comparison method.
            let key_matches: bool =
                subtle::ConstantTimeEq::ct_eq(hex_encoded_client_key.as_ref(), key.as_bytes())
                    .into();
            if !key_matches {
                return Err(Response::builder()
                    .status(403)
                    .body(Some("Forbidden: Invalid key".to_string()))
                    .unwrap());
            }

            location = Some(WebviewWebsocketLocation {
                webview_id,
                server: server_location.clone(),
            });

            Ok(res)
        };

        // Accept the websocket connection while reading the path and setting the location
        let mut websocket = match tungstenite::accept_hdr(
            HandshakeStream::new(stream, handshake_timeout),
            on_request,
        ) {
            Ok(ws) => ws,
            Err(e) => {
                tracing::error!("Error accepting websocket connection: {}", e);
                return;
            }
        };

        let location = match location {
            Some(loc) => loc,
            None => {
                tracing::error!("WebSocket connection without a valid webview ID");
                return;
            }
        };

        // Keep key rotation and activation in the same generation. Holding this lock for the
        // bounded write prevents a pre-rotation handshake from authenticating after rotation.
        let active_server_location = server_location.lock().unwrap();
        if *active_server_location != current_server_location {
            return;
        }

        // Immediately send the key to authenticate the server. A peer can close here.
        if let Err(error) =
            websocket.send(tungstenite::Message::Text(hex_encoded_server_key.into()))
        {
            tracing::debug!(
                "Webview {} closed during server-key authentication: {}",
                location.webview_id,
                error
            );
            return;
        }
        if websocket.get_mut().finish_handshake().is_err() {
            return;
        }

        // Handle the websocket connection in a separate thread
        let (edits_outgoing, edits_incoming_rx) = std::sync::mpsc::channel::<MsgPair>();

        let mut connection_states = connections.write().unwrap();
        let mut pending = match connection_states.remove(&location.webview_id) {
            Some(WebviewConnectionState::Pending { pending }) => pending,
            Some(connected @ WebviewConnectionState::Connected { .. }) => {
                connection_states.insert(location.webview_id, connected);
                tracing::error!(
                    "Webview {} was already connected. Rejecting new connection.",
                    location.webview_id
                );
                return;
            }
            None => VecDeque::new(),
        };
        while let Some(pair) = pending.pop_front() {
            _ = edits_outgoing.send(pair);
        }
        connection_states.insert(
            location.webview_id,
            WebviewConnectionState::Connected {
                generation: current_server_location.generation,
                edits_outgoing,
            },
        );
        drop(connection_states);
        drop(active_server_location);

        let connections_ = connections.clone();
        let webview_id = location.webview_id;
        let generation = current_server_location.generation;
        // Do not spawn a connection thread until the map transition succeeds.
        std::thread::spawn(move || {
            let mut queued_message = None;
            // Wait until there are edits ready to send
            'connection: while let Ok(msg) = edits_incoming_rx.recv() {
                let data = msg.edits.clone();
                queued_message = Some(msg);
                // Send the edits to the webview
                if let Err(e) = websocket.send(tungstenite::Message::Binary(data.into())) {
                    tracing::error!("Error sending edits to webview: {}", e);
                    break 'connection;
                }

                // Wait for the webview to apply the edits
                loop {
                    match websocket.read() {
                        // We expect the webview to send a binary message when it has applied the edits
                        // This is a signal that we can continue processing
                        Ok(tungstenite::Message::Binary(_)) => break,
                        // If the websocket closes, switch back to the pending state and
                        // re-queue the edits that haven't been acknowledged yet
                        Ok(tungstenite::Message::Close(_)) => {
                            break 'connection;
                        }
                        Ok(_) => {}
                        Err(error) => {
                            tracing::debug!(
                                "Webview {} disconnected before acknowledging edits: {}",
                                webview_id,
                                error
                            );
                            break 'connection;
                        }
                    }
                }

                let msg = queued_message.take().expect("Message should be set here");

                // Notify that the edits have been applied
                if msg.response.send(()).is_err() {
                    tracing::error!("Error sending edits applied notification");
                }
            }
            tracing::trace!("Webview {} closed the connection", webview_id);
            Self::transition_to_pending_if_generation(
                &connections_,
                webview_id,
                generation,
                queued_message,
                &edits_incoming_rx,
            );
        });
    }

    fn transition_to_pending_if_generation(
        connections: &Arc<RwLock<HashMap<u32, WebviewConnectionState>>>,
        webview_id: u32,
        generation: u64,
        queued_message: Option<MsgPair>,
        edits_incoming_rx: &std::sync::mpsc::Receiver<MsgPair>,
    ) {
        let mut connections = connections.write().unwrap();
        if matches!(
            connections.get(&webview_id),
            Some(WebviewConnectionState::Connected { generation: active_generation, .. })
                if *active_generation == generation
        ) {
            let mut connection = WebviewConnectionState::default();
            if let Some(msg) = queued_message {
                connection.add_message_pair(msg);
            }
            while let Ok(msg) = edits_incoming_rx.try_recv() {
                connection.add_message_pair(msg);
            }
            connections.insert(webview_id, connection);
        }
    }

    pub(crate) fn create_queue(&self) -> WryQueue {
        let webview_id = self
            .max_webview_id
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let server = self.current_location.clone();
        let server_location = self.server_location.clone();
        WryQueue {
            inner: Rc::new(RefCell::new(WryQueueInner {
                server_location_changed: server_location.clone(),
                server_location_changed_future: owned_notify_future(server_location),
                location: WebviewWebsocketLocation { webview_id, server },
                websocket: self.clone(),
                edits_in_progress: None,
                mutation_state: MutationState::default(),
            })),
        }
    }

    fn send_edits(&mut self, webview: u32, edits: Vec<u8>) -> oneshot::Receiver<()> {
        let mut connections_mut = self.connections.write().unwrap();
        let connection = connections_mut.entry(webview).or_default();
        connection.add_message(edits)
    }
}

/// The state of a webview websocket connection. This may be pending while the webview is booting.
/// If it is, we queue up edits until the webview is ready to receive them.
enum WebviewConnectionState {
    Pending {
        pending: VecDeque<MsgPair>,
    },
    Connected {
        generation: u64,
        edits_outgoing: std::sync::mpsc::Sender<MsgPair>,
    },
}

impl Default for WebviewConnectionState {
    fn default() -> Self {
        WebviewConnectionState::Pending {
            pending: VecDeque::new(),
        }
    }
}

impl WebviewConnectionState {
    /// Add a message to the active connection or queue and return a receiver that will be resolved
    /// when the webview has applied the edits.
    fn add_message(&mut self, edits: Vec<u8>) -> oneshot::Receiver<()> {
        let (response_sender, response_receiver) = oneshot::channel();
        let pair = MsgPair {
            edits,
            response: response_sender,
        };
        self.add_message_pair(pair);
        response_receiver
    }

    /// Add a message pair to the connection state. The receiver in the message pair will be resolved
    /// when the webview has applied the edits.
    fn add_message_pair(&mut self, pair: MsgPair) {
        match self {
            WebviewConnectionState::Pending { pending: queue } => {
                queue.push_back(pair);
            }
            WebviewConnectionState::Connected { edits_outgoing, .. } => {
                _ = edits_outgoing.send(pair);
            }
        }
    }
}

struct MsgPair {
    edits: Vec<u8>,
    response: oneshot::Sender<()>,
}

const KEY_SIZE: usize = 256;
type EncodedKey = [u8; KEY_SIZE];

/// Base64 encode the key to a string to be used in the websocket URL.
fn encode_key_string(key: &EncodedKey) -> String {
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE, key)
}

/// Create a secure key for the websocket connection.
/// Returns the key as a byte array and a hex-encoded string representation of the key.
fn create_secure_key() -> EncodedKey {
    // Helper function to assert that the RNG is a CryptoRng - make sure we use a secure RNG
    fn assert_crypto_random<R: rand::CryptoRng>(val: R) -> R {
        val
    }

    let mut secure_rng = assert_crypto_random(rand::rngs::StdRng::from_os_rng());
    let mut expected_key: EncodedKey = [0u8; KEY_SIZE];
    secure_rng.fill_bytes(&mut expected_key);
    expected_key
}

#[test]
fn test_key_encoding_length() {
    let mut rand = rand::rngs::StdRng::from_os_rng();
    for _ in 0..100 {
        let mut key: EncodedKey = [0u8; KEY_SIZE];
        rand.fill_bytes(&mut key);
        let encoded = encode_key_string(&key);
        // The encoded key length should be the same regardless of the value of the key
        assert_eq!(encoded.len(), 344);
    }
}

#[cfg(test)]
mod transport_tests {
    use super::*;
    use std::io::Write;
    use std::thread;
    use std::time::Instant;

    fn test_queue(limit: usize, timeout: Duration) -> WryQueue {
        EditWebsocket::start_with_handshake_config_for_test(limit, timeout)
            .0
            .create_queue()
    }

    fn test_queue_with_slots(
        limit: usize,
        timeout: Duration,
    ) -> (WryQueue, Arc<HandshakeSlots>) {
        let (websocket, slots) =
            EditWebsocket::start_with_handshake_config_for_test(limit, timeout);
        (websocket.create_queue(), slots)
    }

    fn wait_for_slot_count(slots: &HandshakeSlots, expected: usize, timeout: Duration) {
        let deadline = Instant::now()
            .checked_add(timeout)
            .expect("test slot deadline overflowed");
        while slots.in_use.load(Ordering::Acquire) != expected {
            assert!(
                Instant::now() < deadline,
                "handshake slot count did not reach {expected}"
            );
            thread::yield_now();
        }
    }

    fn wait_for_acknowledgement(
        mut acknowledgement: oneshot::Receiver<()>,
        timeout: Duration,
    ) -> Result<(), oneshot::Canceled> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .expect("test acknowledgement deadline overflowed");
        let waker = std::task::Waker::noop();
        let mut context = std::task::Context::from_waker(waker);
        loop {
            match Pin::new(&mut acknowledgement).poll(&mut context) {
                std::task::Poll::Ready(result) => return result,
                std::task::Poll::Pending => {
                    assert!(
                        Instant::now() < deadline,
                        "edit acknowledgement did not resolve"
                    );
                    thread::yield_now();
                }
            }
        }
    }

    fn connect(queue: &WryQueue) -> tungstenite::WebSocket<TcpStream> {
        let path = queue.edits_path();
        let address = path
            .strip_prefix("ws://")
            .and_then(|value| value.split('/').next())
            .expect("Dioxus websocket URL must include an address");
        let stream = TcpStream::connect(address).expect("test client must connect");
        let (mut websocket, _) = tungstenite::client(path, stream)
            .expect("keyed test client must complete the websocket handshake");
        assert_eq!(
            websocket.read().expect("server key must be sent"),
            tungstenite::Message::Text(queue.required_server_key().into())
        );
        websocket
    }

    fn socket_address(queue: &WryQueue) -> String {
        queue
            .edits_path()
            .strip_prefix("ws://")
            .and_then(|value| value.split('/').next())
            .expect("Dioxus websocket URL must include an address")
            .to_string()
    }

    #[test]
    fn handshake_slot_cap_recovers_after_raii_drop() {
        let slots = Arc::new(HandshakeSlots::new(2));
        let first = slots.try_acquire().expect("first slot must be available");
        let second = slots.try_acquire().expect("second slot must be available");
        assert!(
            slots.try_acquire().is_none(),
            "cap must reject excess handshakes"
        );
        drop(first);
        assert!(
            slots.try_acquire().is_some(),
            "dropped slots must be reusable"
        );
        drop(second);
    }

    #[test]
    fn handshake_slots_release_after_timeouts_and_rejections() {
        const LIMIT: usize = 4;
        const EXCESS: usize = 3;
        let timeout = Duration::from_millis(500);
        let (queue, slots) = test_queue_with_slots(LIMIT, timeout);
        let address = socket_address(&queue);
        let idle_clients = (0..LIMIT)
            .map(|_| TcpStream::connect(&address).expect("idle client must connect"))
            .collect::<Vec<_>>();
        wait_for_slot_count(&slots, LIMIT, Duration::from_secs(1));
        let excess_clients = (0..EXCESS)
            .map(|_| TcpStream::connect(&address).expect("excess client must connect"))
            .collect::<Vec<_>>();
        for rejected in &excess_clients {
            rejected
                .set_read_timeout(Some(Duration::from_millis(500)))
                .expect("test client timeout must be configurable");
            assert!(
                matches!(rejected.peek(&mut [0_u8; 1]), Ok(0)),
                "an excess handshake must be closed immediately"
            );
        }
        drop(excess_clients);
        drop(idle_clients);
        wait_for_slot_count(&slots, 0, Duration::from_secs(1));

        for _ in 0..4 {
            let bad_path = format!("ws://{address}/0/not-the-key");
            assert!(
                tungstenite::client(
                    bad_path,
                    TcpStream::connect(&address).expect("invalid-key client must connect"),
                )
                .is_err()
            );
        }
        drop(connect(&queue));
    }

    #[test]
    fn peer_disconnect_during_handshake_releases_its_slot() {
        let listener =
            TcpListener::bind((IpAddr::from([127, 0, 0, 1]), 0)).expect("test listener must bind");
        let address = listener
            .local_addr()
            .expect("test listener must have an address");
        let location = ServerLocation {
            generation: 0,
            port: address.port(),
            client_key: create_secure_key(),
            server_key: create_secure_key(),
        };
        let server_location = Arc::new(Mutex::new(location));
        let connections = Arc::new(RwLock::new(HashMap::new()));
        let slots = Arc::new(HandshakeSlots::new(1));
        let slot = slots
            .try_acquire()
            .expect("test handshake slot must be available");
        let server_location_ = server_location.clone();
        let connections_ = connections.clone();
        let handler = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("test server must accept");
            EditWebsocket::handle_connection_for_location(
                stream,
                server_location_,
                connections_,
                Duration::from_millis(200),
                slot,
                location,
            );
        });
        drop(TcpStream::connect(address).expect("test peer must connect"));
        handler
            .join()
            .expect("peer close must not panic the handshake worker");
        assert!(
            slots.try_acquire().is_some(),
            "a peer close must release its handshake slot"
        );
    }

    #[test]
    fn peer_disconnect_before_server_key_write_does_not_panic() {
        let (location, listener) = start_server(0);
        let address = listener
            .local_addr()
            .expect("test listener must have an address");
        let server_location = Arc::new(Mutex::new(location));
        let connections = Arc::new(RwLock::new(HashMap::new()));
        let slots = Arc::new(HandshakeSlots::new(1));
        let slot = slots
            .try_acquire()
            .expect("test handshake slot must be available");
        let server_location_ = server_location.clone();
        let connections_ = connections.clone();
        let handler = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("test server must accept");
            EditWebsocket::handle_connection_for_location(
                stream,
                server_location_,
                connections_,
                Duration::from_millis(200),
                slot,
                location,
            );
        });

        let mut peer = TcpStream::connect(address).expect("test peer must connect");
        write!(
            peer,
            "GET /3/{} HTTP/1.1\r\nHost: {address}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
            encode_key_string(&location.client_key)
        )
        .expect("test peer must write a valid upgrade request");
        peer.shutdown(Shutdown::Both)
            .expect("test peer must disconnect before reading the server key");
        drop(peer);

        handler
            .join()
            .expect("server-key peer close must not panic the handshake worker");
        assert!(slots.try_acquire().is_some());
        let acknowledgement = connections
            .write()
            .unwrap()
            .get_mut(&3)
            .map(|connection| connection.add_message(vec![9]));
        if let Some(_acknowledgement) = acknowledgement {
            let cleanup_started = Instant::now();
            while !matches!(
                connections.read().unwrap().get(&3),
                Some(WebviewConnectionState::Pending { .. })
            ) {
                assert!(
                    cleanup_started.elapsed() < Duration::from_millis(500),
                    "the disconnected socket must return to pending state"
                );
                thread::yield_now();
            }
        } else {
            assert!(connections.read().unwrap().is_empty());
        }
    }

    #[test]
    fn keyed_connection_delivers_edits_and_resolves_acknowledgement() {
        let queue = test_queue(2, Duration::from_millis(100));
        let mut websocket = connect(&queue);
        let acknowledgement = queue
            .inner
            .borrow()
            .websocket
            .clone()
            .send_edits(0, vec![1, 2, 3]);
        assert_eq!(
            websocket.read().expect("client must receive edits"),
            tungstenite::Message::Binary(vec![1, 2, 3].into())
        );
        websocket
            .send(tungstenite::Message::Binary(Vec::<u8>::new().into()))
            .expect("client acknowledgement must be accepted");
        assert_eq!(
            wait_for_acknowledgement(acknowledgement, Duration::from_secs(1)),
            Ok(()),
            "the webview must explicitly acknowledge the edit"
        );
    }

    #[test]
    #[should_panic(expected = "An edit acknowledgement was cancelled")]
    fn cancelled_edit_acknowledgement_is_not_treated_as_flushed() {
        let server = Arc::new(Mutex::new(ServerLocation {
            generation: 0,
            port: 0,
            client_key: create_secure_key(),
            server_key: create_secure_key(),
        }));
        let server_location = Arc::new(Notify::new());
        let (sender, receiver) = oneshot::channel();
        drop(sender);
        let queue = WryQueue {
            inner: Rc::new(RefCell::new(WryQueueInner {
                location: WebviewWebsocketLocation {
                    webview_id: 0,
                    server: server.clone(),
                },
                websocket: EditWebsocket {
                    current_location: server,
                    max_webview_id: Default::default(),
                    connections: Default::default(),
                    server_location: server_location.clone(),
                },
                edits_in_progress: Some(receiver),
                server_location_changed: server_location.clone(),
                server_location_changed_future: owned_notify_future(server_location),
                mutation_state: MutationState::default(),
            })),
        };
        let waker = std::task::Waker::noop();
        let mut context = std::task::Context::from_waker(waker);
        let _ = queue.poll_edits_flushed(&mut context);
    }

    #[test]
    fn stale_teardown_cannot_replace_a_live_connection_state() {
        let (sender, receiver) = std::sync::mpsc::channel();
        let connections = Arc::new(RwLock::new(HashMap::from([(
            7,
            WebviewConnectionState::Connected {
                generation: 2,
                edits_outgoing: sender,
            },
        )])));
        EditWebsocket::transition_to_pending_if_generation(&connections, 7, 1, None, &receiver);
        assert!(matches!(
            connections.read().unwrap().get(&7),
            Some(WebviewConnectionState::Connected { generation, .. }) if *generation == 2
        ));
        EditWebsocket::transition_to_pending_if_generation(&connections, 7, 2, None, &receiver);
        assert!(matches!(
            connections.read().unwrap().get(&7),
            Some(WebviewConnectionState::Pending { .. })
        ));
    }

    #[test]
    fn teardown_atomically_preserves_in_flight_and_channel_queued_edits() {
        let (sender, receiver) = std::sync::mpsc::channel();
        let connections = Arc::new(RwLock::new(HashMap::from([(
            7,
            WebviewConnectionState::Connected {
                generation: 2,
                edits_outgoing: sender,
            },
        )])));
        let (in_flight_sender, in_flight_acknowledgement) = oneshot::channel();
        let (queued_sender, queued_acknowledgement) = oneshot::channel();
        let (second_queued_sender, second_queued_acknowledgement) = oneshot::channel();
        let in_flight = MsgPair {
            edits: vec![1],
            response: in_flight_sender,
        };
        let mut connections_mut = connections.write().unwrap();
        connections_mut
            .get_mut(&7)
            .expect("test connection must exist")
            .add_message_pair(MsgPair {
                edits: vec![2],
                response: queued_sender,
            });
        connections_mut
            .get_mut(&7)
            .expect("test connection must exist")
            .add_message_pair(MsgPair {
                edits: vec![3],
                response: second_queued_sender,
            });
        drop(connections_mut);

        EditWebsocket::transition_to_pending_if_generation(
            &connections,
            7,
            2,
            Some(in_flight),
            &receiver,
        );

        let connections_read = connections.read().unwrap();
        let pending = match connections_read.get(&7) {
            Some(WebviewConnectionState::Pending { pending }) => pending,
            _ => panic!("teardown must atomically restore a pending connection"),
        };
        assert_eq!(
            pending
                .iter()
                .map(|message| message.edits.as_slice())
                .collect::<Vec<_>>(),
            vec![&[1][..], &[2][..], &[3][..]],
            "all queued edits must retain FIFO order"
        );
        assert!(in_flight_acknowledgement.now_or_never().is_none());
        assert!(queued_acknowledgement.now_or_never().is_none());
        assert!(second_queued_acknowledgement.now_or_never().is_none());
    }

    #[test]
    fn slow_drip_upgrade_cannot_extend_the_handshake_deadline() {
        let timeout = Duration::from_millis(100);
        let (location, listener) = start_server(0);
        let address = listener
            .local_addr()
            .expect("test listener must have an address");
        let server_location = Arc::new(Mutex::new(location));
        let connections = Arc::new(RwLock::new(HashMap::new()));
        let slots = Arc::new(HandshakeSlots::new(1));
        let slot = slots
            .try_acquire()
            .expect("test handshake slot must be available");
        let handler = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("test server must accept");
            EditWebsocket::handle_connection_for_location(
                stream,
                server_location,
                connections,
                timeout,
                slot,
                location,
            );
        });

        let request = format!(
            "GET /4/{} HTTP/1.1\r\nHost: {address}\r\nUpgrade: websocket\r\n",
            encode_key_string(&location.client_key)
        );
        let mut peer = TcpStream::connect(address).expect("test peer must connect");
        let started = Instant::now();
        for byte in request.bytes() {
            if peer.write_all(&[byte]).is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(15));
        }
        handler
            .join()
            .expect("slow-drip handshake worker must not panic");
        assert!(
            started.elapsed() < timeout * 3,
            "slow-drip input must not extend the absolute handshake deadline"
        );
        assert!(
            slots.try_acquire().is_some(),
            "timed-out handshake must release its slot"
        );
    }

    #[test]
    fn stale_handshake_is_rejected_after_listener_generation_rotation() {
        let (websocket, slots) = EditWebsocket::start_with_handshake_config_for_test(
            1,
            Duration::from_millis(500),
        );
        let queue = websocket.create_queue();
        let old_path = queue.edits_path();
        let captured_location = *queue.inner.borrow().location.server.lock().unwrap();
        let active_location = ServerLocation {
            generation: captured_location.generation + 1,
            port: captured_location.port,
            client_key: create_secure_key(),
            server_key: create_secure_key(),
        };
        *queue.inner.borrow().location.server.lock().unwrap() = active_location;
        let address = old_path
            .strip_prefix("ws://")
            .and_then(|value| value.split('/').next())
            .expect("captured Dioxus path must contain an address")
            .to_string();
        let (mut stale_websocket, _) = tungstenite::client(
            old_path,
            TcpStream::connect(address).expect("stale client must connect"),
        )
        .expect("the captured generation may finish only its HTTP upgrade");
        stale_websocket
            .get_mut()
            .set_read_timeout(Some(Duration::from_millis(500)))
            .expect("stale client timeout must be configurable");
        assert!(
            !matches!(
                stale_websocket.read(),
                Ok(tungstenite::Message::Text(key))
                    if key == encode_key_string(&captured_location.server_key)
            ),
            "a stale listener generation must not authenticate or activate"
        );
        wait_for_slot_count(&slots, 0, Duration::from_secs(1));
        assert!(queue.inner.borrow().websocket.connections.read().unwrap().is_empty());
    }
}

// Take an Arc<Notify> and create a future that waits for the notify to be triggered.
fn owned_notify_future(notify: Arc<Notify>) -> Pin<Box<dyn Future<Output = ()>>> {
    let mut notify_owned = Box::pin(async move {
        let notified = notify.notified();

        // The future should be after this statement once it is polled bellow
        tokio::task::yield_now().await;
        notified.await;
    });

    // Start tracking notify before the output future is polled
    _ = (&mut notify_owned).now_or_never();
    notify_owned
}
