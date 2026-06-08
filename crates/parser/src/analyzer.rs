// analyzer.rs — DNS FSM: матчинг запрос/ответ по txid, детекция аномалий

use std::collections::HashMap;
use serde::Serialize;
use crate::dns::{DnsPacket, QType, RCode};

// ─── Timestamp ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Serialize)]
pub struct Timestamp {
    pub sec: u32,
    pub usec: u32,
}

impl Timestamp {
    pub fn to_f64(self) -> f64 {
        self.sec as f64 + self.usec as f64 / 1_000_000.0
    }
}

// ─── Окно ожидания ответа ────────────────────────────────────────────────────

/// Порог ожидания ответа на запрос (секунды)
const RESPONSE_TIMEOUT_SEC: f64 = 5.0;

/// Порог для детекции NXDOMAIN flood (за скользящее окно)
const NXDOMAIN_FLOOD_WINDOW_SEC: f64 = 10.0;
const NXDOMAIN_FLOOD_THRESHOLD: usize = 20;

/// Порог для детекции retransmit (один txid повторяется)
const RETRANSMIT_THRESHOLD: usize = 3;

/// Порог для детекции slow NXDOMAIN (разведка)
const SLOW_NXDOMAIN_THRESHOLD: usize = 5;

// ─── События ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type")]
pub enum DnsEvent {
    /// Запрос отправлен
    QuerySent {
        txid: u16,
        client: String,
        server: String,
        name: String,
        qtype: String,
    },
    /// Ответ получен (нормальный)
    ResponseReceived {
        txid: u16,
        client: String,
        server: String,
        name: String,
        qtype: String,
        rcode: String,
        answer_count: usize,
        latency_ms: f64,
    },
    /// Запрос без ответа (timeout)
    QueryTimeout {
        txid: u16,
        client: String,
        server: String,
        name: String,
        qtype: String,
    },
    /// Ответ без запроса (unsolicited / спуфинг)
    UnsolicitedResponse {
        txid: u16,
        src: String,
        name: String,
        rcode: String,
    },
    /// Пакет обрезан, клиент должен переспросить по TCP
    TruncatedResponse {
        txid: u16,
        client: String,
        server: String,
        name: String,
    },
    /// NXDOMAIN flood — DGA или сканирование
    NxdomainFlood {
        client: String,
        server: String,
        count: usize,
        window_sec: f64,
        sample_names: Vec<String>,
    },
    /// Медленный поток NXDOMAIN — разведка субдоменов
    SlowNxdomainProbe {
        client: String,
        server: String,
        count: usize,
        names: Vec<String>,
    },
    /// Повторные ретрансмиты одного запроса
    QueryRetransmit {
        txid: u16,
        client: String,
        name: String,
        count: usize,
    },
    /// Подозрение на DNS tunneling (длинные лейблы / высокая энтропия)
    TunnelingIndicator {
        client: String,
        name: String,
        qtype: String,
        reason: String,
    },
    /// TTL аномалия — fast-flux (разные TTL для одного имени)
    TtlAnomaly {
        name: String,
        ttl_min: u32,
        ttl_max: u32,
        server: String,
    },
    /// Ответ пришёл дважды на один txid (спуфинг или rogue resolver)
    DuplicateResponse {
        txid: u16,
        name: String,
        first_src: String,
        second_src: String,
    },
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Serialize)]
pub struct TimedEvent {
    pub ts: f64,
    pub event: DnsEvent,
    pub severity: Severity,
}

pub fn classify_event(ev: &DnsEvent) -> Severity {
    match ev {
        DnsEvent::QuerySent { .. }
        | DnsEvent::ResponseReceived { .. } => Severity::Info,

        DnsEvent::TruncatedResponse { .. }
        | DnsEvent::QueryRetransmit { .. }
        | DnsEvent::UnsolicitedResponse { .. }
        | DnsEvent::QueryTimeout { .. }
        | DnsEvent::TtlAnomaly { .. } => Severity::Warning,

        DnsEvent::NxdomainFlood { .. }
        | DnsEvent::SlowNxdomainProbe { .. }
        | DnsEvent::TunnelingIndicator { .. }
        | DnsEvent::DuplicateResponse { .. } => Severity::Critical,
    }
}

// ─── ReportSummary ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct ReportSummary {
    pub total_queries: usize,
    pub total_responses: usize,
    pub nxdomain_count: usize,
    pub servfail_count: usize,
    pub timeout_count: usize,
    pub anomalies: usize,
    pub unique_clients: usize,
    pub unique_names: usize,
}

// ─── Pending query (ожидает ответа) ─────────────────────────────────────────

#[derive(Debug, Clone)]
struct PendingQuery {
    ts: f64,
    client: String,
    server: String,
    name: String,
    qtype: String,
    /// Сколько раз этот txid уже видели (ретрансмиты)
    retransmit_count: usize,
    /// Уже сгенерировали событие retransmit?
    retransmit_reported: bool,
}

// ─── TTL трекер ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct TtlObservation {
    ttl_min: u32,
    ttl_max: u32,
    reported: bool,
}

// ─── NXDOMAIN трекер (per client→server) ────────────────────────────────────

#[derive(Debug, Clone)]
struct NxdomainTracker {
    /// (timestamp, name)
    entries: Vec<(f64, String)>,
    flood_reported: bool,
    slow_reported: bool,
}

impl NxdomainTracker {
    fn new() -> Self {
        Self { entries: Vec::new(), flood_reported: false, slow_reported: false }
    }

    fn add(&mut self, ts: f64, name: String) {
        self.entries.push((ts, name));
    }

    /// Возвращает количество NXDOMAIN в последнем окне
    fn count_in_window(&self, now: f64) -> usize {
        self.entries.iter()
            .filter(|(t, _)| now - t <= NXDOMAIN_FLOOD_WINDOW_SEC)
            .count()
    }

    fn recent_names(&self, now: f64, limit: usize) -> Vec<String> {
        self.entries.iter()
            .filter(|(t, _)| now - t <= NXDOMAIN_FLOOD_WINDOW_SEC)
            .take(limit)
            .map(|(_, n)| n.clone())
            .collect()
    }

    fn all_names(&self) -> Vec<String> {
        self.entries.iter().map(|(_, n)| n.clone()).collect()
    }
}

// ─── Ключ для pending map ────────────────────────────────────────────────────

/// Ключ: (txid, client_ip, server_ip)
/// txid один — но клиент и сервер уточняют направление
type PendingKey = (u16, String, String);

// ─── Главный анализатор ──────────────────────────────────────────────────────

pub struct Analyzer {
    /// Незакрытые запросы: ключ → PendingQuery
    pending: HashMap<PendingKey, PendingQuery>,
    /// NXDOMAIN трекеры: (client, server) → tracker
    nxdomain: HashMap<(String, String), NxdomainTracker>,
    /// TTL наблюдения: name → TtlObservation
    ttl_obs: HashMap<String, TtlObservation>,
    /// Уже отвеченные txid: для детекции DuplicateResponse
    /// (txid, client, server) → первый src
    answered: HashMap<PendingKey, String>,
    /// Уникальные клиенты
    clients: std::collections::HashSet<String>,
    /// Уникальные запрашиваемые имена
    names: std::collections::HashSet<String>,
}

impl Analyzer {
    pub fn new() -> Self {
        Self {
            pending: HashMap::new(),
            nxdomain: HashMap::new(),
            ttl_obs: HashMap::new(),
            answered: HashMap::new(),
            clients: std::collections::HashSet::new(),
            names: std::collections::HashSet::new(),
        }
    }

    /// Обрабатываем один DNS пакет
    /// src/dst — IP адреса из IP заголовка
    pub fn process(
        &mut self,
        pkt: &DnsPacket,
        src: &str,
        dst: &str,
        ts: Timestamp,
    ) -> Vec<DnsEvent> {
        let mut events = Vec::new();
        let now = ts.to_f64();

        if pkt.is_response {
            self.handle_response(pkt, src, dst, now, &mut events);
        } else {
            self.handle_query(pkt, src, dst, now, &mut events);
        }

        events
    }

    fn handle_query(
        &mut self,
        pkt: &DnsPacket,
        src: &str,
        dst: &str,
        now: f64,
        events: &mut Vec<DnsEvent>,
    ) {
        let name = pkt.first_question_name().unwrap_or("").to_string();
        let qtype = pkt.first_qtype()
            .map(|t| t.as_str())
            .unwrap_or("?")
            .to_string();

        self.clients.insert(src.to_string());
        if !name.is_empty() { self.names.insert(name.clone()); }

        // Tunneling detection
        if pkt.has_long_labels() {
            events.push(DnsEvent::TunnelingIndicator {
                client: src.to_string(),
                name: name.clone(),
                qtype: qtype.clone(),
                reason: "long_label".to_string(),
            });
        }

        // NULL/TXT запрос — частый паттерн DNS tunneling
        if matches!(pkt.first_qtype(), Some(QType::NULL) | Some(QType::TXT)) && !name.is_empty() {
            events.push(DnsEvent::TunnelingIndicator {
                client: src.to_string(),
                name: name.clone(),
                qtype: qtype.clone(),
                reason: "suspicious_qtype".to_string(),
            });
        }

        let key: PendingKey = (pkt.txid, src.to_string(), dst.to_string());

        if let Some(pending) = self.pending.get_mut(&key) {
            // Ретрансмит того же запроса
            pending.retransmit_count += 1;
            if pending.retransmit_count >= RETRANSMIT_THRESHOLD && !pending.retransmit_reported {
                pending.retransmit_reported = true;
                events.push(DnsEvent::QueryRetransmit {
                    txid: pkt.txid,
                    client: src.to_string(),
                    name: name.clone(),
                    count: pending.retransmit_count,
                });
            }
        } else {
            // Новый запрос
            self.pending.insert(key, PendingQuery {
                ts: now,
                client: src.to_string(),
                server: dst.to_string(),
                name: name.clone(),
                qtype: qtype.clone(),
                retransmit_count: 0,
                retransmit_reported: false,
            });

            events.push(DnsEvent::QuerySent {
                txid: pkt.txid,
                client: src.to_string(),
                server: dst.to_string(),
                name: name.clone(),
                qtype,
            });
        }
    }

    fn handle_response(
        &mut self,
        pkt: &DnsPacket,
        src: &str,
        dst: &str,
        now: f64,
        events: &mut Vec<DnsEvent>,
    ) {
        let name = pkt.first_question_name().unwrap_or("").to_string();
        let rcode = pkt.rcode.as_str().to_string();
        let answer_count = pkt.answers.len();

        // Ключ: ответ идёт dst→src относительно запроса
        let key: PendingKey = (pkt.txid, dst.to_string(), src.to_string());

        // Truncated response
        if pkt.truncated {
            events.push(DnsEvent::TruncatedResponse {
                txid: pkt.txid,
                client: dst.to_string(),
                server: src.to_string(),
                name: name.clone(),
            });
        }

        // TTL anomaly detection для ответов с записями
        for ans in &pkt.answers {
            if ans.rtype == QType::OPT { continue; }
            if ans.ttl == 0 { continue; } // TTL=0 — валидный negative caching

            let entry = self.ttl_obs.entry(ans.name.clone()).or_insert(TtlObservation {
                ttl_min: ans.ttl,
                ttl_max: ans.ttl,
                reported: false,
            });

            entry.ttl_min = entry.ttl_min.min(ans.ttl);
            entry.ttl_max = entry.ttl_max.max(ans.ttl);

            // Fast-flux: разброс TTL > 10x
            if !entry.reported && entry.ttl_max > 0 && entry.ttl_min > 0 {
                let ratio = entry.ttl_max as f64 / entry.ttl_min as f64;
                if ratio >= 10.0 {
                    entry.reported = true;
                    events.push(DnsEvent::TtlAnomaly {
                        name: ans.name.clone(),
                        ttl_min: entry.ttl_min,
                        ttl_max: entry.ttl_max,
                        server: src.to_string(),
                    });
                }
            }
        }

        if let Some(pending) = self.pending.remove(&key) {
            let latency_ms = (now - pending.ts) * 1000.0;

            // Duplicate response detection
            if let Some(first_src) = self.answered.get(&key) {
                events.push(DnsEvent::DuplicateResponse {
                    txid: pkt.txid,
                    name: name.clone(),
                    first_src: first_src.clone(),
                    second_src: src.to_string(),
                });
            } else {
                self.answered.insert(key.clone(), src.to_string());
            }

            events.push(DnsEvent::ResponseReceived {
                txid: pkt.txid,
                client: dst.to_string(),
                server: src.to_string(),
                name: name.clone(),
                qtype: pending.qtype,
                rcode: rcode.clone(),
                answer_count,
                latency_ms,
            });

            // NXDOMAIN tracking
            if pkt.rcode == RCode::NXDomain {
                let tracker_key = (dst.to_string(), src.to_string());
                let tracker = self.nxdomain
                    .entry(tracker_key.clone())
                    .or_insert_with(NxdomainTracker::new);

                tracker.add(now, name.clone());

                let count_in_window = tracker.count_in_window(now);

                // Flood detection
                if !tracker.flood_reported && count_in_window >= NXDOMAIN_FLOOD_THRESHOLD {
                    tracker.flood_reported = true;
                    let sample = tracker.recent_names(now, 5);
                    events.push(DnsEvent::NxdomainFlood {
                        client: dst.to_string(),
                        server: src.to_string(),
                        count: count_in_window,
                        window_sec: NXDOMAIN_FLOOD_WINDOW_SEC,
                        sample_names: sample,
                    });
                }

                // Slow probe detection (за всё время, не в окне)
                let total = tracker.entries.len();
                if !tracker.slow_reported
                    && total >= SLOW_NXDOMAIN_THRESHOLD
                    && count_in_window < NXDOMAIN_FLOOD_THRESHOLD
                {
                    tracker.slow_reported = true;
                    events.push(DnsEvent::SlowNxdomainProbe {
                        client: dst.to_string(),
                        server: src.to_string(),
                        count: total,
                        names: tracker.all_names(),
                    });
                }
            }

        } else {
            // Ответ без запроса — unsolicited / возможный спуфинг
            events.push(DnsEvent::UnsolicitedResponse {
                txid: pkt.txid,
                src: src.to_string(),
                name: name.clone(),
                rcode,
            });
        }
    }

    /// Вызывается в конце обработки — закрываем оставшиеся pending запросы как timeout
    pub fn finalize(&mut self, last_ts: Timestamp) -> Vec<DnsEvent> {
        let now = last_ts.to_f64();
        let mut events = Vec::new();

        for (_, pending) in self.pending.drain() {
            let age = now - pending.ts;
            if age >= RESPONSE_TIMEOUT_SEC {
                events.push(DnsEvent::QueryTimeout {
                    txid: 0, // txid уже не важен
                    client: pending.client,
                    server: pending.server,
                    name: pending.name,
                    qtype: pending.qtype,
                });
            }
        }

        events
    }

    pub fn unique_clients(&self) -> usize { self.clients.len() }
    pub fn unique_names(&self) -> usize { self.names.len() }
}
