use clap::Parser;

/// Configuration for the bitcredit application
/// Allows to set the ports and addresses for the network connections
/// either via command line or environment variables
#[derive(Parser, Clone)]
#[command(version, about, long_about = None)]
pub struct Config {
    #[arg(default_value_t = 8000, long, env = "HTTP_PORT")]
    pub http_port: u16,
    #[arg(default_value_t = String::from("127.0.0.1"), long, env = "HTTP_ADDRESS")]
    pub http_address: String,
    #[arg(default_value_t = String::from("."), long, env = "DATA_DIR")]
    pub data_dir: String,
    #[arg(default_value_t = String::from("ws://localhost:8800"), long, env = "SURREAL_DB_CONNECTION")]
    pub surreal_db_connection: String,
    #[arg(default_value_t = String::from("testnet"),  long, env = "BITCOIN_NETWORK")]
    pub bitcoin_network: String,
    #[arg(default_value = "ws://localhost:8080", value_delimiter = ',', num_args = 1.., long, env = "NOSTR_RELAYS")]
    pub nostr_relays: Vec<String>,
    #[arg(default_value_t = String::from("https://moksha.minibill.tech"), long, env = "MINT_URL")]
    pub mint_url: String,
    #[arg(default_value_t = 1, long, env = "JOB_RUNNER_INITIAL_DELAY_SECONDS")]
    pub job_runner_initial_delay_seconds: u64,
    #[arg(default_value_t = 600, long, env = "JOB_RUNNER_CHECK_INTERVAL_SECONDS")]
    pub job_runner_check_interval_seconds: u64,
    #[arg(default_value_t = String::from("frontend"), long, env = "FRONTEND_SERVE_FOLDER")]
    pub frontend_serve_folder: String,
    #[arg(default_value_t = String::from("/"), long, env = "FRONTEND_URL_PATH")]
    pub frontend_url_path: String,
    #[arg(default_value_t = false, long, env = "LAUNCH_FRONTEND_AT_STARTUP")]
    pub launch_frontend_at_startup: bool,
    #[arg(default_value_t = String::from("https://blockstream.info"), long, env = "ESPLORA_BASE_URL")]
    pub esplora_base_url: String,
}

impl Config {
    pub fn http_listen_url(&self) -> String {
        format!("http://{}:{}", self.http_address, self.http_port)
    }
}
