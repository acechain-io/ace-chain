use ace_p2p::config::{validate_bootnodes, NetworkConfig};

#[test]
fn default_config() {
    let config = NetworkConfig::default();
    assert_eq!(config.listen_addr, "/ip4/0.0.0.0/tcp/30333");
    assert!(config.bootnodes.is_empty());
    assert_eq!(config.node_name, "ace-node");
}

#[test]
fn custom_config() {
    let peer_id = libp2p::identity::Keypair::generate_ed25519()
        .public()
        .to_peer_id();
    let config = NetworkConfig {
        listen_addr: "/ip4/127.0.0.1/tcp/9000".to_string(),
        bootnodes: vec![format!("/ip4/10.0.0.1/tcp/30333/p2p/{peer_id}")],
        node_name: "my-validator".to_string(),
        max_peers: 50,
        enable_mdns: false,
        data_dir: None,
        ..Default::default()
    };
    assert_eq!(config.listen_addr, "/ip4/127.0.0.1/tcp/9000");
    assert_eq!(config.bootnodes.len(), 1);
}

#[test]
fn bootnodes_require_peer_ids() {
    let err = validate_bootnodes(&["/ip4/127.0.0.1/tcp/30333".to_string()])
        .expect_err("bootnodes without peer ids must be rejected");
    assert!(err.contains("/p2p/<peer-id>"));
}
