KEMALG = "ML-KEM-768"
AUTH_SIGALG = "Ed25519"
APP_SALT = b"mini-lattice-onion-v4"
DEFAULT_TIMEOUT = 10.0


# Fixed stream-cell payload budget (bytes) after base64 decoding.
CELL_PAYLOAD_BYTES = 512
# Upper bound for grouped stream cells in one relay-side processing unit.
MAX_BATCH_CELLS = 16
