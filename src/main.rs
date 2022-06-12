use anyhow::Ok;
use pnet::packet::{
    icmp::{
        destination_unreachable::DestinationUnreachable,
        echo_reply::EchoReplyPacket,
        echo_request::{IcmpCodes, MutableEchoRequestPacket},
        time_exceeded::TimeExceededPacket,
        IcmpPacket,
        IcmpTypes::{self, TimestampReply},
    },
    ip::IpNextHeaderProtocols,
    util, Packet, PacketData,
};
use pnet_transport::icmp_packet_iter;
use pnet_transport::TransportChannelType::Layer4;
use pnet_transport::{transport_channel, TransportProtocol};
use rand::random;
use std::{
    env,
    net::IpAddr,
    process::id,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

const ICMP_SIZE: usize = 10;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        panic!("Usage: icmp-demo target_ip");
    }
    let target_ip: IpAddr = args[1].parse().unwrap();
    println!("icmp echo request to target ip:{:#?}", target_ip);

    let protocol = Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp));
    let (mut tx, mut rx) = match transport_channel(4096, protocol) {
        std::result::Result::Ok((tx, rx)) => (tx, rx),
        Err(e) => return Err(e.into()),
    };

    std::thread::spawn(move || {
        let mut iter = icmp_packet_iter(&mut rx);
        loop {
            let timer = Arc::new(RwLock::new(Instant::now()));
            match iter.next() {
                std::result::Result::Ok((packet, addr)) => {
                    let start_time = timer.read().unwrap();
                    let rtt = Instant::now().duration_since(*start_time);
                    match packet.get_icmp_type() {
                        IcmpTypes::EchoReply => {
                            let reply = EchoReplyPacket::new(packet.packet()).unwrap();
                            let identifier = reply.get_identifier();
                            let sequence_number = reply.get_sequence_number();
                            println!(
                            "ICMP EchoReply received from {:?}: {:?} , Time:{:?}; identify: {}, seq: {}",
                            addr,
                            packet.get_icmp_type(),
                            rtt,
                            identifier,
                            sequence_number
                        );
                        }
                        IcmpTypes::TimeExceeded => {
                            let reply = TimeExceededPacket::new(packet.packet()).unwrap();
                            println!(
                                "ICMP TimeExceeded received from {:?}: {:?} , Time:{:?}",
                                addr,
                                packet.get_icmp_type(),
                                rtt,
                            );
                        }
                        IcmpTypes::DestinationUnreachable => {
                            println!(
                                "ICMP DestinationUnreachable received from {:?}, Time:{:?}",
                                addr, rtt
                            );
                        }
                        _ => {
                            println!("get package {:?}, {:?}", packet.get_icmp_type(), addr);
                            // println!("get icmp reply: {:?}", t)
                        }
                    }
                }
                Err(e) => {
                    println!("An error occurred while reading: {}", e);
                    break;
                }
            }

            std::thread::sleep(Duration::from_millis(500));
        }
    });

    // create a new thread
    let mut ttl = 0;
    while ttl < 30 {
        ttl += 1;
        let mut icmp_header: [u8; ICMP_SIZE] = [0; ICMP_SIZE];
        let icmp_packet = create_icmp_packet(&mut icmp_header, ttl);
        // println!("icmp_packet:{:?}", icmp_packet);
        tx.set_ttl(ttl);
        tx.send_to(icmp_packet, target_ip);
        std::thread::sleep(std::time::Duration::from_secs(1))
    }
    Ok(())
}

fn create_icmp_packet<'a>(icmp_header: &'a mut [u8], seq: u8) -> MutableEchoRequestPacket<'a> {
    let mut icmp_packet = MutableEchoRequestPacket::new(icmp_header).unwrap();
    icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
    icmp_packet.set_icmp_code(IcmpCodes::NoCode);
    icmp_packet.set_identifier(random::<u16>());
    icmp_packet.set_sequence_number(seq as u16);
    let checksum = util::checksum(icmp_packet.packet(), 1);
    icmp_packet.set_checksum(checksum);

    icmp_packet
}
