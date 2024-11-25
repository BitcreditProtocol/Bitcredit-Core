# E-Bills

Core for Bitcredit project.

### Backend

Make sure to have a recent version of the Rust toolchain installed.

Start the backend server in development mode:

```bash
# Run with defaults
RUST_LOG=info cargo run

# configure listening ports and addresses
RUST_LOG=info cargo run -- --http-port 8001 --http-address 0.0.0.0

# Configuration can also be set via environment variables
export P2P_PORT=1909
export P2P_ADDRESS=0.0.0.0

# Run with embedded database feature, data stored in data/surreal
cargo run --features embedded-db -- --surreal-db-connection rocksdb://data/surreal
```

### Frontend

Make sure to have a recent version of Node.js installed.

Build the frontend:

```bash
cd frontend
npm install --legacy-peer-deps
npm run build
```

### Development

Start the app in development mode with frontend and backend hot reloading
(requires two terminals):

```bash
# Terminal 1
RUST_LOG=info cargo watch -x run  # watch can be installed with cargo install cargo-watch

# Terminal 2
cd frontend
npm run start
```

### Tests

You can run the existing tests using the following commands:

```bash
// without logs
cargo test

// with logs - (env_logger needs to be activated in the test to show logs)
RUST_LOG=info cargo test -- --nocapture
```

### Docker

The docker build requires no dependencies other than docker or podman. It can
also be used to run multiple instances of the app on different ports for testing
the P2P functionality.

#### Build a standalone docker image

Build the image:

```bash
# The image name can be changed to whatever you want
docker build -t <image-name> .
```

Launch the image:

```bash
docker run -p 8000:8000 -p 1908:1908 -e RUST_LOG=info <image-name>
```

You should be able to open the app at [http://127.0.0.1:8000/bitcredit/]([http://127.0.0.1:8000/bitcredit/])

#### Run with docker-compose

Build and launch the app with docker-compose running on a different port than
the default 8000:

```bash
# run in foreground, can be stopped using CTRL+C
docker-compose up

# run in background, can be stopped using docker-compose stop
docker-compose up -d

# rebuild the image
docker-compose build
```

If you use the above commands, the application state (identity, bills, contacts)
will persist between sessions. However, if you use `docker-compose down`, or
`docker-compose rm`, the existing container gets removed, along with it's state.
Of course, rebuilding the image also removes the application state.

### SurrealDB

For development it is advised to use a local SurrealDB instance running as a
separate service as compile times are quite long. In production builds SurrealDB
will be available as an embedded database in the application. SurrealDB listens
on port 8000 by default which is the same as the default port for the application
so make sure to change the SurrealDB port or application port before running the
services.

#### Connect to SurrealDB

When the application has been built with the `embedded-db` feature, it allows to
use the application with a `rocksdb://path/to/db` connection string otherwise you
need to connect the the database via web-socket like: `ws://localhost:8800`.

#### Run SurrealDB for development

```bash
# build the application with surrealdb embedded
cargo build --features embedded-db

# start surrealdb container included in docker-compose.yml (listening 8800)
docker-compose up -d surrealdb

# with surrealdb installed on your local machine (listening on port 8800)
surrealdb start --unauthenticated --bind 127.0.0.1:8800
```

#### Explore the database with Surrealist

To work with and explore the database, you can use
[Surrealist](https://surrealdb.com/surrealist) which is an interactive interface
for SurrealDB.

## Contribute

Check out the project [contributing guide](./CONTRIBUTING.md).
