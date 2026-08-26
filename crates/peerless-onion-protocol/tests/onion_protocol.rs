use peerless_onion_protocol::{
    fragment_message, max_payload_for_hops, CellType, CircuitSender, Direction, HopDuplex, HopKeys,
    HopReceiver, InitiatorSetup, OnionError, OpenedLayer, Reassembler, RelayOnionSecret,
    RelaySetup, SetupContext, SetupRequest, SetupResponse, WireCell, CELL_SIZE, MAX_FRAGMENT_COUNT,
    MAX_HOPS, MAX_MESSAGE_SIZE, SETUP_REQUEST_SIZE, SETUP_RESPONSE_SIZE,
};

const NOW: u64 = 10_000;

fn context(hop: u8) -> SetupContext {
    SetupContext {
        circuit_id: [0x51; 16],
        hop,
        epoch: 166,
        expires_at: NOW + 60,
    }
}

fn handshake(context: SetupContext) -> (HopKeys, HopKeys) {
    let relay_secret = RelayOnionSecret::generate();
    let (request, pending) =
        InitiatorSetup::start(context, relay_secret.public_key(), NOW).unwrap();
    let (response, relay) = RelaySetup::accept(&request, &relay_secret, NOW).unwrap();
    let initiator = InitiatorSetup::finish(pending, &response, NOW).unwrap();
    (initiator, relay)
}

fn route(hops: usize) -> (Vec<HopKeys>, Vec<HopKeys>) {
    let mut initiator = Vec::new();
    let mut relays = Vec::new();
    for hop in 0..hops {
        let (left, right) = handshake(context(hop as u8));
        initiator.push(left);
        relays.push(right);
    }
    (initiator, relays)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[test]
fn setup_round_trip_and_every_field_mutation_fail_closed() {
    let setup_offsets = [0, 4, 6, 7, 8, 24, 32, 40, 72, 104];
    for offset in setup_offsets {
        let relay_secret = RelayOnionSecret::generate();
        let (request, pending) =
            InitiatorSetup::start(context(0), relay_secret.public_key(), NOW).unwrap();
        let mut bytes = *request.as_bytes();
        bytes[offset] ^= 1;
        let outcome = SetupRequest::from_bytes(&bytes)
            .and_then(|changed| {
                RelaySetup::accept(&changed, &relay_secret, NOW).map(|value| value.0)
            })
            .and_then(|response| InitiatorSetup::finish(pending, &response, NOW));
        assert!(
            outcome.is_err(),
            "setup request offset {offset} was accepted"
        );
    }

    let response_offsets = [0, 4, 6, 7, 8, 24, 32, 40, 72, 104, 136, 152];
    for offset in response_offsets {
        let relay_secret = RelayOnionSecret::generate();
        let (request, pending) =
            InitiatorSetup::start(context(0), relay_secret.public_key(), NOW).unwrap();
        let (response, _) = RelaySetup::accept(&request, &relay_secret, NOW).unwrap();
        let mut bytes = *response.as_bytes();
        bytes[offset] ^= 1;
        let outcome = SetupResponse::from_bytes(&bytes)
            .and_then(|changed| InitiatorSetup::finish(pending, &changed, NOW));
        assert!(
            outcome.is_err(),
            "setup response offset {offset} was accepted"
        );
    }

    assert_eq!(
        SetupRequest::from_bytes(&[0; SETUP_REQUEST_SIZE - 1]),
        Err(OnionError::InvalidEncoding)
    );
    assert_eq!(
        SetupResponse::from_bytes(&[0; SETUP_RESPONSE_SIZE + 1]),
        Err(OnionError::InvalidEncoding)
    );
    let relay_secret = RelayOnionSecret::generate();
    let (expired, _) = InitiatorSetup::start(context(0), relay_secret.public_key(), NOW).unwrap();
    assert_eq!(
        RelaySetup::accept(&expired, &relay_secret, NOW + 60).err(),
        Some(OnionError::Expired)
    );

    let expected_relay = RelayOnionSecret::generate();
    let impostor = RelayOnionSecret::generate();
    let (request, _) = InitiatorSetup::start(context(0), expected_relay.public_key(), NOW).unwrap();
    assert_eq!(
        RelaySetup::accept(&request, &impostor, NOW).err(),
        Some(OnionError::WrongScope)
    );
}

#[test]
fn three_hops_remove_exactly_one_layer_and_hide_inner_type_and_payload() {
    let (initiator, relays) = route(MAX_HOPS);
    let secret_payload = b"terminal-secret-marker-terminal-secret-marker";
    let mut sender = CircuitSender::new(initiator, Direction::Forward).unwrap();
    let mut cell = sender.seal(CellType::Data, secret_payload).unwrap();
    assert_eq!(cell.as_bytes().len(), CELL_SIZE);
    assert!(!contains(cell.as_bytes(), secret_payload));

    for (index, relay) in relays.into_iter().enumerate() {
        let mut receiver = HopReceiver::new(relay, Direction::Forward);
        let opened = receiver.open(&cell, NOW).unwrap();
        if index + 1 == MAX_HOPS {
            assert_eq!(
                opened,
                OpenedLayer::Terminal {
                    cell_type: CellType::Data,
                    payload: secret_payload.to_vec(),
                }
            );
        } else {
            cell = match opened {
                OpenedLayer::Forward(next) => *next,
                OpenedLayer::Terminal { .. } => panic!("relay exposed a terminal inner type"),
            };
            assert_eq!(cell.as_bytes().len(), CELL_SIZE);
            assert!(!contains(cell.as_bytes(), secret_payload));
        }
    }
}

#[test]
fn every_terminal_type_round_trips_as_fixed_size() {
    let types = [
        CellType::Setup,
        CellType::Data,
        CellType::Padding,
        CellType::Response,
        CellType::Rotation,
        CellType::Teardown,
    ];
    let (initiator, relay) = handshake(context(0));
    let mut sender = CircuitSender::new(vec![initiator], Direction::Forward).unwrap();
    let mut receiver = HopReceiver::new(relay, Direction::Forward);
    for (index, cell_type) in types.into_iter().enumerate() {
        let payload = vec![index as u8; index * 37];
        let cell = sender.seal(cell_type, &payload).unwrap();
        assert_eq!(cell.as_bytes().len(), CELL_SIZE);
        assert_eq!(
            receiver.open(&cell, NOW).unwrap(),
            OpenedLayer::Terminal { cell_type, payload }
        );
    }
}

#[test]
fn forward_reverse_wrong_direction_and_wrong_key_are_not_substitutable() {
    let (forward_sender_key, forward_relay_key) = handshake(context(0));
    let mut forward_sender =
        CircuitSender::new(vec![forward_sender_key], Direction::Forward).unwrap();
    let forward = forward_sender.seal(CellType::Data, b"forward").unwrap();
    let mut wrong_direction = HopReceiver::new(forward_relay_key, Direction::Reverse);
    assert_eq!(
        wrong_direction.open(&forward, NOW),
        Err(OnionError::WrongScope)
    );

    let (_, unrelated_relay_key) = handshake(context(0));
    let mut wrong_key = HopReceiver::new(unrelated_relay_key, Direction::Forward);
    assert_eq!(
        wrong_key.open(&forward, NOW),
        Err(OnionError::AuthenticationFailed)
    );

    let (reverse_initiator_key, reverse_relay_key) = handshake(context(0));
    let mut reverse_sender =
        CircuitSender::new(vec![reverse_relay_key], Direction::Reverse).unwrap();
    let reverse = reverse_sender.seal(CellType::Response, b"reverse").unwrap();
    let mut reverse_receiver = HopReceiver::new(reverse_initiator_key, Direction::Reverse);
    assert_eq!(
        reverse_receiver.open(&reverse, NOW).unwrap(),
        OpenedLayer::Terminal {
            cell_type: CellType::Response,
            payload: b"reverse".to_vec(),
        }
    );
}

#[test]
fn wrong_hop_fails_and_three_hop_reverse_path_is_layered() {
    let (initiator, mut relays) = route(MAX_HOPS);
    let mut sender = CircuitSender::new(initiator, Direction::Forward).unwrap();
    let cell = sender.seal(CellType::Data, b"hop-bound").unwrap();
    let wrong_hop_key = relays.remove(1);
    let mut wrong_hop = HopReceiver::new(wrong_hop_key, Direction::Forward);
    assert_eq!(
        wrong_hop.open(&cell, NOW),
        Err(OnionError::AuthenticationFailed)
    );

    let (initiator, relays) = route(MAX_HOPS);
    let mut relay_hops = relays.into_iter().map(HopDuplex::new).collect::<Vec<_>>();
    let mut reverse = relay_hops[2]
        .seal_terminal(Direction::Reverse, CellType::Response, b"layered-reverse")
        .unwrap();
    reverse = relay_hops[1].wrap(Direction::Reverse, &reverse).unwrap();
    reverse = relay_hops[0].wrap(Direction::Reverse, &reverse).unwrap();
    for (index, key) in initiator.into_iter().enumerate() {
        let mut receiver = HopReceiver::new(key, Direction::Reverse);
        match receiver.open(&reverse, NOW).unwrap() {
            OpenedLayer::Forward(next) if index + 1 < MAX_HOPS => reverse = *next,
            OpenedLayer::Terminal { cell_type, payload } if index + 1 == MAX_HOPS => {
                assert_eq!(cell_type, CellType::Response);
                assert_eq!(payload, b"layered-reverse");
            }
            _ => panic!("reverse path exposed the wrong layer"),
        }
    }
}

#[test]
fn every_cell_field_ciphertext_tag_and_padding_mutation_fails_without_burning_sequence() {
    let offsets = [0, 4, 6, 7, 8, 24, 32, 40, 48, 50, 75, CELL_SIZE - 1];
    for offset in offsets {
        let (sender_key, receiver_key) = handshake(context(0));
        let mut sender = CircuitSender::new(vec![sender_key], Direction::Forward).unwrap();
        let original = sender.seal(CellType::Data, b"authenticated").unwrap();
        let mut bytes = *original.as_bytes();
        bytes[offset] ^= 1;
        let mut receiver = HopReceiver::new(receiver_key, Direction::Forward);
        let outcome = WireCell::from_bytes(&bytes).and_then(|cell| receiver.open(&cell, NOW));
        assert!(outcome.is_err(), "cell offset {offset} was accepted");
        assert!(receiver.open(&original, NOW).is_ok());
    }
}

#[test]
fn replay_reordering_and_window_bounds_are_enforced_after_authentication() {
    let (sender_key, receiver_key) = handshake(context(0));
    let mut sender = CircuitSender::new(vec![sender_key], Direction::Forward).unwrap();
    let cells = (0..=130)
        .map(|_| sender.seal(CellType::Padding, &[]).unwrap())
        .collect::<Vec<_>>();
    let mut receiver = HopReceiver::new(receiver_key, Direction::Forward);
    receiver.open(&cells[0], NOW).unwrap();
    receiver.open(&cells[2], NOW).unwrap();
    receiver.open(&cells[1], NOW).unwrap();
    assert_eq!(receiver.open(&cells[1], NOW), Err(OnionError::Replay));
    assert_eq!(receiver.open(&cells[67], NOW), Err(OnionError::OutOfWindow));
    for cell in &cells[3..=66] {
        receiver.open(cell, NOW).unwrap();
    }
    for cell in &cells[67..=130] {
        receiver.open(cell, NOW).unwrap();
    }
    assert_eq!(receiver.open(&cells[0], NOW), Err(OnionError::OutOfWindow));
}

#[test]
fn fixed_cell_size_and_hop_payload_bounds_hold_for_small_and_large_messages() {
    for hops in 1..=MAX_HOPS {
        for size in [0, 1, max_payload_for_hops(hops).unwrap()] {
            let (initiator, _) = route(hops);
            let mut sender = CircuitSender::new(initiator, Direction::Forward).unwrap();
            let cell = sender.seal(CellType::Data, &vec![0x7a; size]).unwrap();
            assert_eq!(cell.as_bytes().len(), CELL_SIZE);
        }
        let (initiator, _) = route(hops);
        let mut sender = CircuitSender::new(initiator, Direction::Forward).unwrap();
        assert_eq!(
            sender
                .seal(
                    CellType::Data,
                    &vec![0; max_payload_for_hops(hops).unwrap() + 1]
                )
                .err(),
            Some(OnionError::PayloadTooLarge)
        );
    }
    assert_eq!(max_payload_for_hops(0), Err(OnionError::HopLimit));
    assert_eq!(
        max_payload_for_hops(MAX_HOPS + 1),
        Err(OnionError::HopLimit)
    );
}

#[test]
fn cell_parser_rejects_truncation_oversize_and_invalid_declared_lengths() {
    let (sender_key, _) = handshake(context(0));
    let mut sender = CircuitSender::new(vec![sender_key], Direction::Forward).unwrap();
    let cell = sender.seal(CellType::Data, b"bounded").unwrap();
    assert_eq!(
        WireCell::from_bytes(&cell.as_bytes()[..CELL_SIZE - 1]),
        Err(OnionError::InvalidEncoding)
    );
    let mut oversized = cell.as_bytes().to_vec();
    oversized.push(0);
    assert_eq!(
        WireCell::from_bytes(&oversized),
        Err(OnionError::InvalidEncoding)
    );
    let mut impossible = *cell.as_bytes();
    impossible[48..50].copy_from_slice(&u16::MAX.to_be_bytes());
    assert_eq!(
        WireCell::from_bytes(&impossible),
        Err(OnionError::InvalidEncoding)
    );
}

#[test]
fn fragmentation_reassembly_property_boundaries_and_duplicate_rejection() {
    let sizes = [
        0,
        1,
        peerless_onion_protocol::Fragment::MAX_BYTES - 1,
        peerless_onion_protocol::Fragment::MAX_BYTES,
        peerless_onion_protocol::Fragment::MAX_BYTES + 1,
        100_000,
        MAX_MESSAGE_SIZE,
    ];
    for size in sizes {
        let message = (0..size)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let fragments = fragment_message([size as u8; 16], &message).unwrap();
        assert!(fragments.len() <= MAX_FRAGMENT_COUNT as usize);
        for fragment in &fragments {
            assert_eq!(
                peerless_onion_protocol::Fragment::decode(&fragment.encode().unwrap()).unwrap(),
                *fragment
            );
        }
        let mut reassembler = Reassembler::default();
        let mut output = None;
        for fragment in fragments.into_iter().rev() {
            output = reassembler.push(fragment).unwrap().or(output);
        }
        assert_eq!(output, Some(message));
    }

    assert_eq!(
        fragment_message([0; 16], &vec![0; MAX_MESSAGE_SIZE + 1]),
        Err(OnionError::PayloadTooLarge)
    );
    let fragments = fragment_message([9; 16], &[3; 2_000]).unwrap();
    let mut reassembler = Reassembler::default();
    reassembler.push(fragments[0].clone()).unwrap();
    assert_eq!(
        reassembler.push(fragments[0].clone()),
        Err(OnionError::Replay)
    );
}

#[test]
fn parser_fuzz_corpus_and_hostile_fragment_metadata_fail_safely() {
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    for length in 0..=CELL_SIZE * 2 {
        let mut bytes = vec![0u8; length];
        for byte in &mut bytes {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = state as u8;
        }
        let _ = WireCell::from_bytes(&bytes);
        let _ = SetupRequest::from_bytes(&bytes);
        let _ = SetupResponse::from_bytes(&bytes);
        let _ = peerless_onion_protocol::Fragment::decode(&bytes);
    }

    let fragment = fragment_message([0x33; 16], b"partial-message")
        .unwrap()
        .remove(0);
    let mut oversized_count = fragment.encode().unwrap();
    oversized_count[20..24].copy_from_slice(&(MAX_FRAGMENT_COUNT + 1).to_be_bytes());
    assert_eq!(
        peerless_onion_protocol::Fragment::decode(&oversized_count),
        Err(OnionError::InvalidEncoding)
    );
    let mut oversized_total = fragment.encode().unwrap();
    oversized_total[24..28].copy_from_slice(&((MAX_MESSAGE_SIZE as u32) + 1).to_be_bytes());
    assert_eq!(
        peerless_onion_protocol::Fragment::decode(&oversized_total),
        Err(OnionError::InvalidEncoding)
    );
}

#[test]
fn secret_debug_output_is_redacted() {
    let relay_secret = RelayOnionSecret::generate();
    assert!(format!("{relay_secret:?}").contains("[REDACTED]"));
    let (request, pending) =
        InitiatorSetup::start(context(0), relay_secret.public_key(), NOW).unwrap();
    assert!(format!("{pending:?}").contains("[REDACTED]"));
    let (_, keys) = RelaySetup::accept(&request, &relay_secret, NOW).unwrap();
    let debug = format!("{keys:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("forward_key"));
}
