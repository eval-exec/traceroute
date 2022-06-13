extern crate core;

use std::{
    env,
    net::IpAddr,
    sync::{Arc, RwLock},
    time::Instant,
};

use anyhow::{Ok, Result};
use pnet::packet::icmpv6::Icmpv6Types;
use pnet::packet::{
    icmp::{
        echo_reply::EchoReplyPacket,
        echo_request::{IcmpCodes, MutableEchoRequestPacket},
        time_exceeded::TimeExceededPacket,
        IcmpTypes,
    },
    icmpv6::{echo_request::Icmpv6Codes::NoCode, Icmpv6Types::EchoRequest},
    ip::IpNextHeaderProtocols,
    util, Packet,
};
use pnet_transport::icmp_packet_iter;
use pnet_transport::TransportChannelType::Layer4;
use pnet_transport::{transport_channel, TransportProtocol};
use rand::random;

const ICMP_SIZE: usize = 10;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        panic!("Usage: icmp target_ip");
    }

    // resolve domain args[1]
    let hosts = dns_lookup::lookup_host(args[1].as_str()).unwrap();
    if hosts.is_empty() {
        panic!("dns query failed")
    }
    let target_ip = *hosts.first().unwrap();

    let is_ipv4 = target_ip.is_ipv4();
    println!(
        "icmp request(ipv4{:?}) to target ip:{:#?}",
        is_ipv4, target_ip
    );

    let protocol = match target_ip.is_ipv4() {
        true => Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp)),
        false => Layer4(TransportProtocol::Ipv6(IpNextHeaderProtocols::Icmpv6)),
    };
    let (mut tx, mut rx) = match transport_channel(4096, protocol) {
        Result::Ok((tx, rx)) => (tx, rx),
        Err(e) => return Err(e.into()),
    };

    std::thread::spawn(move || {
        // create a new thread
        let mut ttl = 0;
        while ttl < 30 {
            ttl += 1;
            let mut icmp_header: [u8; ICMP_SIZE] = [0; ICMP_SIZE];
            tx.set_ttl(ttl);
            if is_ipv4 {
                let icmp_packet = create_icmpv4_packet(&mut icmp_header, ttl);
                // println!("icmp_packet:{:?}", icmp_packet);
                tx.send_to(icmp_packet, target_ip)
                    .expect("send packet error");
            } else {
                let icmp_packet = create_icmpv6_packet(&mut icmp_header, ttl);
                // println!("icmp_packet:{:?}", icmp_packet);
                tx.send_to(icmp_packet, target_ip)
                    .expect("send packet error");
            }
            std::thread::sleep(std::time::Duration::from_secs(1))
        }
    });

    std::thread::spawn(move || {
        if is_ipv4 {
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
                                break;
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
                            IcmpTypes::Timestamp => {
                                println!(
                                    "ICMP Timestamp received from {:?}, Time:{:?}",
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

                std::thread::sleep(std::time::Duration::from_millis(500));
            }
        } else {
            let mut iter = pnet_transport::icmpv6_packet_iter(&mut rx);
            loop {
                let timer = Arc::new(RwLock::new(Instant::now()));
                match iter.next() {
                    std::result::Result::Ok((packet, addr)) => {
                        let start_time = timer.read().unwrap();
                        let rtt = Instant::now().duration_since(*start_time);
                        match packet.get_icmpv6_type() {
                            pnet::packet::icmpv6::Icmpv6Types::EchoReply => {
                                let reply = pnet::packet::icmpv6::echo_reply::EchoReplyPacket::new(packet.packet()).unwrap();
                                let identifier = reply.get_identifier();
                                let sequence_number = reply.get_sequence_number();
                                println!(
                                    "ICMPv6 EchoReply received from {:?}: {:?} , Time:{:?}; identify: {}, seq: {}",
                                    addr,
                                    packet.get_icmpv6_type(),
                                    rtt,
                                    identifier,
                                    sequence_number
                                );
                                break;
                            }
                            pnet::packet::icmpv6::Icmpv6Types::TimeExceeded => {
                                let reply = TimeExceededPacket::new(packet.packet()).unwrap();
                                println!(
                                    "ICMPv6 TimeExceeded received from {:?}: {:?} , Time:{:?}",
                                    addr,
                                    packet.get_icmpv6_type(),
                                    rtt,
                                );
                            }
                            pnet::packet::icmpv6::Icmpv6Types::DestinationUnreachable => {
                                println!(
                                    "ICMPv6 DestinationUnreachable received from {:?}, Time:{:?}",
                                    addr, rtt
                                );
                            }
                            pnet::packet::icmpv6::Icmpv6Types::NeighborSolicit => {
                                println!(
                                    "ICMPv6 NeighborSolicit received from {:?}, Time:{:?}",
                                    addr, rtt
                                );
                            }
                            pnet::packet::icmpv6::Icmpv6Types::RouterAdvert => {
                                println!(
                                    "ICMPv6 RouterAdvert received from {:?}, Time:{:?}",
                                    addr, rtt
                                );
                            }
                            pnet::packet::icmpv6::Icmpv6Types::NeighborAdvert => {
                                println!(
                                    "ICMPv6 NeighborAdvert received from {:?}, Time:{:?}",
                                    addr, rtt
                                );
                            }
                            _ => {
                                println!("get package {:?}, {:?}", packet.get_icmpv6_type(), addr);
                                // println!("get icmp reply: {:?}", t)
                            }
                        }
                    }
                    Err(e) => {
                        println!("An error occurred while reading: {}", e);
                        break;
                    }
                }

                std::thread::sleep(std::time::Duration::from_millis(500));
            }
        }
    }).join().unwrap();
    Ok(())
}

fn create_icmpv4_packet<'a>(icmp_header: &'a mut [u8], seq: u8) -> MutableEchoRequestPacket<'a> {
    let mut icmp_packet = MutableEchoRequestPacket::new(icmp_header).unwrap();
    icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
    icmp_packet.set_icmp_code(IcmpCodes::NoCode);
    icmp_packet.set_identifier(random::<u16>());
    icmp_packet.set_sequence_number(seq as u16);
    let checksum = util::checksum(icmp_packet.packet(), 1);
    icmp_packet.set_checksum(checksum);

    icmp_packet
}

fn create_icmpv6_packet<'a>(
    icmp_header: &'a mut [u8],
    seq: u8,
) -> pnet::packet::icmpv6::echo_request::MutableEchoRequestPacket<'a> {
    let mut icmp_packet =
        pnet::packet::icmpv6::echo_request::MutableEchoRequestPacket::new(icmp_header).unwrap();
    icmp_packet.set_icmpv6_type(EchoRequest);
    icmp_packet.set_icmpv6_code(NoCode);
    icmp_packet.set_identifier(random::<u16>());
    icmp_packet.set_sequence_number(seq as u16);
    let checksum = util::checksum(icmp_packet.packet(), 1);
    icmp_packet.set_checksum(checksum);

    icmp_packet
}
