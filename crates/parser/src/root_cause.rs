// root_cause.rs — корреляция аномалий в каузальные цепочки
// Аналог dhcp-postmortem/root_cause.rs

use serde::Serialize;
use crate::analyzer::{TimedEvent, DnsEvent, Severity};

// ─── Типы root cause ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, PartialEq)]
pub enum RootCauseKind {
    /// DNS tunneling — exfiltration или C2
    DnsTunneling,
    /// DGA активность — malware или ботнет
    DgaActivity,
    /// Разведка субдоменов
    SubdomainProbing,
    /// Rogue/спуфинг resolver
    RogueResolver,
    /// Недоступен DNS сервер
    ServerUnreachable,
    /// Fast-flux инфраструктура
    FastFlux,
    /// Нестабильная сеть (много ретрансмитов)
    NetworkInstability,
    /// Норма — аномалий нет
    Clean,
}

impl RootCauseKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            RootCauseKind::DnsTunneling      => "DNS Tunneling",
            RootCauseKind::DgaActivity       => "DGA Activity",
            RootCauseKind::SubdomainProbing  => "Subdomain Probing",
            RootCauseKind::RogueResolver     => "Rogue Resolver",
            RootCauseKind::ServerUnreachable => "Server Unreachable",
            RootCauseKind::FastFlux          => "Fast-Flux Infrastructure",
            RootCauseKind::NetworkInstability => "Network Instability",
            RootCauseKind::Clean             => "Clean",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            RootCauseKind::DnsTunneling =>
                "Detected DNS queries with unusually long labels or suspicious record types \
                 (NULL/TXT). This pattern is consistent with DNS tunneling used for data \
                 exfiltration or C2 communication.",
            RootCauseKind::DgaActivity =>
                "High volume of NXDOMAIN responses in a short window indicates Domain \
                 Generation Algorithm (DGA) activity. This is a common malware technique \
                 to locate C2 servers.",
            RootCauseKind::SubdomainProbing =>
                "Slow but persistent NXDOMAIN stream targeting subdomains of a single \
                 domain. Consistent with subdomain enumeration or reconnaissance.",
            RootCauseKind::RogueResolver =>
                "Duplicate responses to the same transaction ID from different sources, \
                 or unsolicited responses. Indicates a rogue resolver or DNS spoofing attempt.",
            RootCauseKind::ServerUnreachable =>
                "Multiple queries without any response. DNS server may be down, \
                 filtered, or misconfigured.",
            RootCauseKind::FastFlux =>
                "Significant TTL variation observed for the same domain name across \
                 multiple responses. Consistent with fast-flux infrastructure used to \
                 obscure malicious hosting.",
            RootCauseKind::NetworkInstability =>
                "High retransmission rate observed. Queries are being repeated multiple \
                 times without receiving responses, indicating packet loss or network \
                 congestion.",
            RootCauseKind::Clean =>
                "No anomalies detected. Traffic appears consistent with normal DNS \
                 operation.",
        }
    }
}

// ─── Каузальная цепочка ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct CausalChain {
    pub kind: String,
    pub description: String,
    /// Метки времени событий-улик
    pub evidence_ts: Vec<f64>,
    /// Краткое описание каждой улики
    pub evidence_notes: Vec<String>,
    pub severity: String,
}

/// Итоговый отчёт root cause
#[derive(Debug, Clone, Serialize)]
pub struct RootCauseReport {
    /// Основная причина (самая критичная)
    pub primary: String,
    pub primary_description: String,
    /// Все найденные цепочки
    pub chains: Vec<CausalChain>,
    /// Есть ли что-то критичное
    pub has_critical: bool,
}

// ─── Корреляция ──────────────────────────────────────────────────────────────

pub fn correlate(events: &[TimedEvent]) -> RootCauseReport {
    let mut chains: Vec<CausalChain> = Vec::new();

    // 1. DNS Tunneling
    if let Some(chain) = detect_tunneling(events) {
        chains.push(chain);
    }

    // 2. DGA / NXDOMAIN flood
    if let Some(chain) = detect_dga(events) {
        chains.push(chain);
    }

    // 3. Subdomain probing
    if let Some(chain) = detect_subdomain_probe(events) {
        chains.push(chain);
    }

    // 4. Rogue resolver / спуфинг
    if let Some(chain) = detect_rogue_resolver(events) {
        chains.push(chain);
    }

    // 5. Server unreachable
    if let Some(chain) = detect_server_unreachable(events) {
        chains.push(chain);
    }

    // 6. Fast-flux
    if let Some(chain) = detect_fast_flux(events) {
        chains.push(chain);
    }

    // 7. Network instability
    if let Some(chain) = detect_instability(events) {
        chains.push(chain);
    }

    let has_critical = chains.iter().any(|c| c.severity == "Critical");

    // Выбираем primary: сначала Critical, потом Warning, иначе Clean
    let primary_kind = chains.iter()
        .find(|c| c.severity == "Critical")
        .or_else(|| chains.iter().find(|c| c.severity == "Warning"))
        .map(|c| RootCauseKind::from_str(&c.kind))
        .unwrap_or(RootCauseKind::Clean);

    let primary_description = if chains.is_empty() {
        RootCauseKind::Clean.description().to_string()
    } else {
        primary_kind.description().to_string()
    };

    RootCauseReport {
        primary: primary_kind.as_str().to_string(),
        primary_description,
        chains,
        has_critical,
    }
}

// ─── Детекторы ───────────────────────────────────────────────────────────────

fn detect_tunneling(events: &[TimedEvent]) -> Option<CausalChain> {
    let indicators: Vec<&TimedEvent> = events.iter()
        .filter(|e| matches!(e.event, DnsEvent::TunnelingIndicator { .. }))
        .collect();

    if indicators.is_empty() { return None; }

    let mut notes = Vec::new();
    let mut ts_list = Vec::new();

    for te in &indicators {
        ts_list.push(te.ts);
        match &te.event {
            DnsEvent::TunnelingIndicator { name, qtype, reason, .. } => {
                let reason_str = match reason.as_str() {
                    "long_label"       => "long subdomain label",
                    "suspicious_qtype" => "suspicious record type",
                    other              => other,
                };
                notes.push(format!("{} ({}, {})", name, qtype, reason_str));
            }
            _ => {}
        }
    }

    Some(CausalChain {
        kind: RootCauseKind::DnsTunneling.as_str().to_string(),
        description: RootCauseKind::DnsTunneling.description().to_string(),
        evidence_ts: ts_list,
        evidence_notes: notes,
        severity: "Critical".to_string(),
    })
}

fn detect_dga(events: &[TimedEvent]) -> Option<CausalChain> {
    let floods: Vec<&TimedEvent> = events.iter()
        .filter(|e| matches!(e.event, DnsEvent::NxdomainFlood { .. }))
        .collect();

    if floods.is_empty() { return None; }

    let mut notes = Vec::new();
    let mut ts_list = Vec::new();

    for te in &floods {
        ts_list.push(te.ts);
        if let DnsEvent::NxdomainFlood { count, window_sec, sample_names, client, .. } = &te.event {
            notes.push(format!(
                "{} NXDOMAIN in {:.0}s from {} (e.g. {})",
                count, window_sec, client,
                sample_names.first().map(|s| s.as_str()).unwrap_or("?")
            ));
        }
    }

    Some(CausalChain {
        kind: RootCauseKind::DgaActivity.as_str().to_string(),
        description: RootCauseKind::DgaActivity.description().to_string(),
        evidence_ts: ts_list,
        evidence_notes: notes,
        severity: "Critical".to_string(),
    })
}

fn detect_subdomain_probe(events: &[TimedEvent]) -> Option<CausalChain> {
    let probes: Vec<&TimedEvent> = events.iter()
        .filter(|e| matches!(e.event, DnsEvent::SlowNxdomainProbe { .. }))
        .collect();

    if probes.is_empty() { return None; }

    let mut notes = Vec::new();
    let mut ts_list = Vec::new();

    for te in &probes {
        ts_list.push(te.ts);
        if let DnsEvent::SlowNxdomainProbe { count, names, client, .. } = &te.event {
            // Пытаемся найти общий базовый домен
            let base = common_base_domain(names);
            notes.push(format!(
                "{} NXDOMAIN from {} targeting {}",
                count, client,
                base.unwrap_or_else(|| "multiple domains".to_string())
            ));
        }
    }

    Some(CausalChain {
        kind: RootCauseKind::SubdomainProbing.as_str().to_string(),
        description: RootCauseKind::SubdomainProbing.description().to_string(),
        evidence_ts: ts_list,
        evidence_notes: notes,
        severity: "Critical".to_string(),
    })
}

fn detect_rogue_resolver(events: &[TimedEvent]) -> Option<CausalChain> {
    let dupes: Vec<&TimedEvent> = events.iter()
        .filter(|e| matches!(e.event,
            DnsEvent::DuplicateResponse { .. } | DnsEvent::UnsolicitedResponse { .. }
        ))
        .collect();

    if dupes.is_empty() { return None; }

    let mut notes = Vec::new();
    let mut ts_list = Vec::new();

    for te in &dupes {
        ts_list.push(te.ts);
        match &te.event {
            DnsEvent::DuplicateResponse { name, first_src, second_src, .. } => {
                notes.push(format!(
                    "Duplicate response for {} from {} and {}",
                    name, first_src, second_src
                ));
            }
            DnsEvent::UnsolicitedResponse { src, name, rcode, .. } => {
                notes.push(format!(
                    "Unsolicited {} from {} for {}",
                    rcode, src, name
                ));
            }
            _ => {}
        }
    }

    Some(CausalChain {
        kind: RootCauseKind::RogueResolver.as_str().to_string(),
        description: RootCauseKind::RogueResolver.description().to_string(),
        evidence_ts: ts_list,
        evidence_notes: notes,
        severity: "Critical".to_string(),
    })
}

fn detect_server_unreachable(events: &[TimedEvent]) -> Option<CausalChain> {
    let timeouts: Vec<&TimedEvent> = events.iter()
        .filter(|e| matches!(e.event, DnsEvent::QueryTimeout { .. }))
        .collect();

    // Порог: 3+ timeout'а
    if timeouts.len() < 3 { return None; }

    let mut notes = Vec::new();
    let mut ts_list = Vec::new();

    // Группируем по серверу
    let mut by_server: HashMap<String, usize> = HashMap::new();
    for te in &timeouts {
        ts_list.push(te.ts);
        if let DnsEvent::QueryTimeout { server, name, .. } = &te.event {
            *by_server.entry(server.clone()).or_default() += 1;
            notes.push(format!("No response for {} from server {}", name, server));
        }
    }

    // Оставляем только топ-3 заметки
    notes.truncate(3);
    for (server, count) in &by_server {
        if *count > 1 {
            notes.push(format!("{} total timeouts to {}", count, server));
        }
    }

    Some(CausalChain {
        kind: RootCauseKind::ServerUnreachable.as_str().to_string(),
        description: RootCauseKind::ServerUnreachable.description().to_string(),
        evidence_ts: ts_list,
        evidence_notes: notes,
        severity: "Warning".to_string(),
    })
}

fn detect_fast_flux(events: &[TimedEvent]) -> Option<CausalChain> {
    let anomalies: Vec<&TimedEvent> = events.iter()
        .filter(|e| matches!(e.event, DnsEvent::TtlAnomaly { .. }))
        .collect();

    if anomalies.is_empty() { return None; }

    let mut notes = Vec::new();
    let mut ts_list = Vec::new();

    for te in &anomalies {
        ts_list.push(te.ts);
        if let DnsEvent::TtlAnomaly { name, ttl_min, ttl_max, .. } = &te.event {
            notes.push(format!(
                "{}: TTL range {}s–{}s ({}x variation)",
                name, ttl_min, ttl_max,
                ttl_max / (*ttl_min).max(1)
            ));
        }
    }

    Some(CausalChain {
        kind: RootCauseKind::FastFlux.as_str().to_string(),
        description: RootCauseKind::FastFlux.description().to_string(),
        evidence_ts: ts_list,
        evidence_notes: notes,
        severity: "Warning".to_string(),
    })
}

fn detect_instability(events: &[TimedEvent]) -> Option<CausalChain> {
    let retransmits: Vec<&TimedEvent> = events.iter()
        .filter(|e| matches!(e.event, DnsEvent::QueryRetransmit { .. }))
        .collect();

    if retransmits.is_empty() { return None; }

    let mut notes = Vec::new();
    let mut ts_list = Vec::new();

    for te in &retransmits {
        ts_list.push(te.ts);
        if let DnsEvent::QueryRetransmit { client, name, count, .. } = &te.event {
            notes.push(format!(
                "{} retransmits for {} from {}",
                count, name, client
            ));
        }
    }

    Some(CausalChain {
        kind: RootCauseKind::NetworkInstability.as_str().to_string(),
        description: RootCauseKind::NetworkInstability.description().to_string(),
        evidence_ts: ts_list,
        evidence_notes: notes,
        severity: "Warning".to_string(),
    })
}

// ─── Вспомогательные функции ─────────────────────────────────────────────────

/// Пытаемся найти общий базовый домен из списка имён
/// Например ["foo.evil.com", "bar.evil.com"] → "evil.com"
fn common_base_domain(names: &[String]) -> Option<String> {
    if names.is_empty() { return None; }
    if names.len() == 1 {
        return Some(names[0].clone());
    }

    // Берём последние 2 части первого имени как кандидат базового домена
    let base_candidate: Vec<&str> = names[0].split('.').rev().take(2).collect();
    if base_candidate.len() < 2 { return None; }

    let base = format!("{}.{}", base_candidate[1], base_candidate[0]);

    // Проверяем что все имена заканчиваются на этот базовый домен
    let all_match = names.iter().all(|n| n.ends_with(&base));
    if all_match { Some(base) } else { None }
}

impl RootCauseKind {
    fn from_str(s: &str) -> Self {
        match s {
            "DNS Tunneling"           => RootCauseKind::DnsTunneling,
            "DGA Activity"            => RootCauseKind::DgaActivity,
            "Subdomain Probing"       => RootCauseKind::SubdomainProbing,
            "Rogue Resolver"          => RootCauseKind::RogueResolver,
            "Server Unreachable"      => RootCauseKind::ServerUnreachable,
            "Fast-Flux Infrastructure"=> RootCauseKind::FastFlux,
            "Network Instability"     => RootCauseKind::NetworkInstability,
            _                         => RootCauseKind::Clean,
        }
    }
}

use std::collections::HashMap;
