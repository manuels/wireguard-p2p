use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Message {
    pub timestamp: std::time::SystemTime,
    pub ip_addr_list: Vec<std::net::SocketAddr>,
}
