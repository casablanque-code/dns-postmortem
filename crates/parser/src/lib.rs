// lib.rs — WASM entrypoint для dns-postmortem
#![allow(dead_code, unused_imports, unused_variables)]

mod pcap;
mod pcapng;
mod net;
mod dns;
mod analyzer;
mod root_cause;

use wasm_bindgen::prelude::*;
use analyzer::{Analyzer, TimedEvent, ReportSummary, classify_event, Severity};
use net::{PROTO_UDP, PROTO_TCP, DNS_PORT};

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

macro_rules! console_log {
    ($($t:tt)*) => (log(&format_args!($($t)*).to_string()))
}

#[wasm_bindgen]
pub fn analyze_pcap(data: &[u8]) -> Result<JsValue, JsValue> {
    let is_pcapng = data.len() >= 4 &&
        u32::from_le_bytes([data[0], data[1], data[2], data[3]]) == 0x0A0D0D0Au32;

    let unified: Vec<(u32, u32, Vec<u8>)> = if is_pcapng {
        console_log!("Detected PCAPng format");
        pcapng::parse_pcapng(data)
            .map_err(|e| JsValue::from_str(e.as_str()))?
    } else {
        console_log!("Detected legacy PCAP format");
        let (_, pkts) = pcap::iter_packets(data)
            .map_err(|e| JsValue::from_str(e.as_str()))?;
        pkts.iter().map(|p| (p.ts_sec, p.ts_usec, p.data.to_vec())).collect()
    };

    console_log!("Parsed: {} packets", unified.len());

    let mut analyzer = Analyzer::new();
    let mut events: Vec<TimedEvent> = Vec::new();
    let mut dns_count = 0usize;
    let mut last_ts = analyzer::Timestamp { sec: 0, usec: 0 };

    let first_ts = unified.first()
        .map(|(s, u, _)| *s as f64 + *u as f64 / 1e6)
        .unwrap_or(0.0);

    for (ts_sec, ts_usec, pkt_data) in &unified {
        let ts = analyzer::Timestamp { sec: *ts_sec, usec: *ts_usec };
        last_ts = ts;

        let Some((ip, payload)) = net::extract_ip(pkt_data) else { continue };

        match ip.protocol {
            p if p == PROTO_UDP => {
                let Some((src_port, dst_port, udp_payload)) = net::extract_udp(payload) else { continue };
                if !net::is_dns_port(src_port, dst_port) { continue; }

                let Some(pkt) = dns::parse_dns(udp_payload) else { continue };
                dns_count += 1;

                let new_events = analyzer.process(&pkt, &ip.src_str(), &ip.dst_str(), ts);
                push_events(new_events, ts, &mut events);
            }

            p if p == PROTO_TCP => {
                let Some(seg) = net::extract_tcp(payload) else { continue };
                if !net::is_dns_port(seg.src_port, seg.dst_port) { continue };
                if seg.payload.is_empty() { continue; }

                // DNS over TCP: 2-байтовый length prefix
                let Some(pkt) = dns::parse_dns_tcp(seg.payload) else { continue };
                dns_count += 1;

                let new_events = analyzer.process(&pkt, &ip.src_str(), &ip.dst_str(), ts);
                push_events(new_events, ts, &mut events);
            }

            _ => continue,
        }
    }

    // Закрываем оставшиеся pending запросы
    let final_events = analyzer.finalize(last_ts);
    push_events(final_events, last_ts, &mut events);

    let root_cause = root_cause::correlate(&events);

    // Статистика
    let anomalies = events.iter().filter(|e|
        matches!(e.severity, Severity::Warning | Severity::Critical)
    ).count();

    let total_queries = events.iter().filter(|e|
        matches!(e.event, analyzer::DnsEvent::QuerySent { .. })
    ).count();

    let total_responses = events.iter().filter(|e|
        matches!(e.event, analyzer::DnsEvent::ResponseReceived { .. })
    ).count();

    let nxdomain_count = events.iter().filter(|e|
        matches!(&e.event, analyzer::DnsEvent::ResponseReceived { rcode, .. } if rcode == "NXDOMAIN")
    ).count();

    let servfail_count = events.iter().filter(|e|
        matches!(&e.event, analyzer::DnsEvent::ResponseReceived { rcode, .. } if rcode == "SERVFAIL")
    ).count();

    let timeout_count = events.iter().filter(|e|
        matches!(e.event, analyzer::DnsEvent::QueryTimeout { .. })
    ).count();

    let report = FullReport {
        total_packets: unified.len(),
        dns_packets: dns_count,
        duration_sec: last_ts.to_f64() - first_ts,
        events,
        summary: ReportSummary {
            total_queries,
            total_responses,
            nxdomain_count,
            servfail_count,
            timeout_count,
            anomalies,
            unique_clients: analyzer.unique_clients(),
            unique_names: analyzer.unique_names(),
        },
        root_cause,
    };

    serde_wasm_bindgen::to_value(&report).map_err(|e| JsValue::from_str(&e.to_string()))
}

fn push_events(new_events: Vec<analyzer::DnsEvent>, ts: analyzer::Timestamp, out: &mut Vec<TimedEvent>) {
    for ev in new_events {
        let severity = classify_event(&ev);
        out.push(TimedEvent { ts: ts.to_f64(), event: ev, severity });
    }
}

#[derive(serde::Serialize)]
struct FullReport {
    total_packets: usize,
    dns_packets: usize,
    duration_sec: f64,
    events: Vec<TimedEvent>,
    summary: ReportSummary,
    root_cause: root_cause::RootCauseReport,
}

pub use analyzer::Timestamp;
