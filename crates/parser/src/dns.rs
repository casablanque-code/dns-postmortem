// dns.rs — парсер DNS пакетов (RFC 1035 + EDNS0 RFC 6891)

/// Тип DNS запроса
#[derive(Debug, Clone, PartialEq)]
pub enum QType {
    A,
    AAAA,
    NS,
    CNAME,
    MX,
    TXT,
    PTR,
    SOA,
    SRV,
    OPT,   // EDNS0 pseudo-record
    NULL,  // type 10 — используется в DNS tunneling
    Other(u16),
}

impl QType {
    pub fn from_u16(v: u16) -> Self {
        match v {
            1    => QType::A,
            2    => QType::NS,
            5    => QType::CNAME,
            6    => QType::SOA,
            10   => QType::NULL,
            12   => QType::PTR,
            15   => QType::MX,
            16   => QType::TXT,
            28   => QType::AAAA,
            33   => QType::SRV,
            41   => QType::OPT,
            n    => QType::Other(n),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            QType::A        => "A",
            QType::AAAA     => "AAAA",
            QType::NS       => "NS",
            QType::CNAME    => "CNAME",
            QType::MX       => "MX",
            QType::TXT      => "TXT",
            QType::PTR      => "PTR",
            QType::SOA      => "SOA",
            QType::SRV      => "SRV",
            QType::OPT      => "OPT",
            QType::NULL     => "NULL",
            QType::Other(_) => "OTHER",
        }
    }
}

/// DNS response code
#[derive(Debug, Clone, PartialEq)]
pub enum RCode {
    NoError,
    FormErr,
    ServFail,
    NXDomain,
    NotImp,
    Refused,
    Other(u8),
}

impl RCode {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => RCode::NoError,
            1 => RCode::FormErr,
            2 => RCode::ServFail,
            3 => RCode::NXDomain,
            4 => RCode::NotImp,
            5 => RCode::Refused,
            n => RCode::Other(n),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            RCode::NoError   => "NOERROR",
            RCode::FormErr   => "FORMERR",
            RCode::ServFail  => "SERVFAIL",
            RCode::NXDomain  => "NXDOMAIN",
            RCode::NotImp    => "NOTIMP",
            RCode::Refused   => "REFUSED",
            RCode::Other(_)  => "OTHER",
        }
    }
}

/// DNS вопрос (Question section)
#[derive(Debug, Clone)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: QType,
    pub qclass: u16,
}

/// Resource Record (Answer/Authority/Additional)
#[derive(Debug, Clone)]
pub struct DnsRecord {
    pub name: String,
    pub rtype: QType,
    pub rclass: u16,
    pub ttl: u32,
    pub rdata: Vec<u8>,
    /// Для A/AAAA — распарсенный IP
    pub parsed_addr: Option<String>,
    /// Для CNAME/NS/PTR — распарсенное имя
    pub parsed_name: Option<String>,
}

/// EDNS0 OPT pseudo-record (RFC 6891)
#[derive(Debug, Clone)]
pub struct EdnsInfo {
    /// UDP payload size, заявленная клиентом/сервером
    pub udp_payload_size: u16,
    /// Extended RCODE (верхние 8 бит)
    pub ext_rcode: u8,
    /// EDNS version
    pub version: u8,
    /// DO bit (DNSSEC OK)
    pub dnssec_ok: bool,
}

/// Распарсенный DNS пакет
#[derive(Debug, Clone)]
pub struct DnsPacket {
    /// Transaction ID
    pub txid: u16,
    /// true = Response, false = Query
    pub is_response: bool,
    /// Opcode (0 = QUERY, 1 = IQUERY, 2 = STATUS)
    pub opcode: u8,
    /// Authoritative Answer
    pub aa: bool,
    /// Truncated (TC bit) — пакет обрезан, нужен TCP retry
    pub truncated: bool,
    /// Recursion Desired
    pub rd: bool,
    /// Recursion Available
    pub ra: bool,
    /// Response code
    pub rcode: RCode,
    /// Question section
    pub questions: Vec<DnsQuestion>,
    /// Answer section
    pub answers: Vec<DnsRecord>,
    /// Authority section
    pub authority: Vec<DnsRecord>,
    /// Additional section (без OPT)
    pub additional: Vec<DnsRecord>,
    /// EDNS0 информация если есть OPT record
    pub edns: Option<EdnsInfo>,
}

impl DnsPacket {
    /// Первый вопрос (обычно один)
    pub fn first_question_name(&self) -> Option<&str> {
        self.questions.first().map(|q| q.name.as_str())
    }

    pub fn first_qtype(&self) -> Option<&QType> {
        self.questions.first().map(|q| &q.qtype)
    }

    /// Есть ли подозрение на DNS tunneling по длине имени
    pub fn has_long_labels(&self) -> bool {
        self.questions.iter().any(|q| {
            // Суммарная длина имени > 100 или любой лейбл > 30 — подозрительно
            q.name.len() > 100 || q.name.split('.').any(|label| label.len() > 30)
        })
    }
}

// ─── Парсинг имён (RFC 1035 §4.1.4) ────────────────────────────────────────

/// Максимальная глубина поинтеров — защита от циклов
const MAX_PTR_DEPTH: usize = 10;
/// Максимальная длина распарсенного имени
const MAX_NAME_LEN: usize = 255;

/// Декодируем DNS имя с поддержкой компрессии.
/// `data` — весь DNS пакет (нужен для pointer'ов)
/// `offset` — позиция начала имени
/// Возвращает (имя, новый offset после имени в исходном потоке)
pub fn decode_name(data: &[u8], offset: usize) -> Option<(String, usize)> {
    decode_name_inner(data, offset, 0)
}

fn decode_name_inner(data: &[u8], offset: usize, depth: usize) -> Option<(String, usize)> {
    if depth > MAX_PTR_DEPTH { return None; } // защита от циклов

    let mut labels: Vec<String> = Vec::new();
    let mut pos = offset;
    let jumped = false;
    let mut end_offset = 0usize;

    loop {
        if pos >= data.len() { return None; }
        let len_byte = data[pos];

        if len_byte == 0 {
            // Конец имени
            if !jumped { end_offset = pos + 1; }
            break;
        }

        // Проверяем тип: pointer или label
        let tag = (len_byte & 0xC0) >> 6;
        match tag {
            0 => {
                // Обычный лейбл: следующие len_byte байт
                let label_len = len_byte as usize;
                if pos + 1 + label_len > data.len() { return None; }
                let label = std::str::from_utf8(&data[pos + 1..pos + 1 + label_len]).ok()?;
                labels.push(label.to_string());
                pos += 1 + label_len;

                // Проверяем суммарную длину
                let total: usize = labels.iter().map(|l| l.len() + 1).sum();
                if total > MAX_NAME_LEN { return None; }
            }
            3 => {
                // Pointer: 0xC0 | high_byte, затем low_byte
                if pos + 1 >= data.len() { return None; }
                let ptr = (((len_byte & 0x3F) as usize) << 8) | data[pos + 1] as usize;

                if ptr >= data.len() { return None; }
                if ptr == offset || ptr == pos { return None; } // прямой цикл

                if !jumped { end_offset = pos + 2; }
                let _ = jumped; // pointer encountered, further offsets come from recursion

                // Рекурсивно разрешаем pointer
                let (suffix, _) = decode_name_inner(data, ptr, depth + 1)?;
                if !suffix.is_empty() {
                    labels.push(suffix);
                }
                break;
            }
            _ => {
                // Reserved (01, 10) — неизвестный формат, пропускаем
                return None;
            }
        }
    }

    let name = labels.join(".");
    Some((name, end_offset))
}

// ─── Парсинг секций ─────────────────────────────────────────────────────────

fn parse_question(data: &[u8], offset: usize) -> Option<(DnsQuestion, usize)> {
    let (name, pos) = decode_name(data, offset)?;
    if pos + 4 > data.len() { return None; }
    let qtype  = u16::from_be_bytes([data[pos], data[pos + 1]]);
    let qclass = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
    Some((DnsQuestion { name, qtype: QType::from_u16(qtype), qclass }, pos + 4))
}

fn parse_record(data: &[u8], offset: usize) -> Option<(DnsRecord, usize)> {
    let (name, pos) = decode_name(data, offset)?;
    if pos + 10 > data.len() { return None; }

    let rtype  = u16::from_be_bytes([data[pos],     data[pos + 1]]);
    let rclass = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
    let ttl    = u32::from_be_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]]);
    let rdlen  = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
    let rdata_start = pos + 10;

    if rdata_start + rdlen > data.len() { return None; }
    let rdata = data[rdata_start..rdata_start + rdlen].to_vec();
    let qtype = QType::from_u16(rtype);

    // Парсим rdata для известных типов
    let parsed_addr = match &qtype {
        QType::A if rdlen == 4 => {
            Some(format!("{}.{}.{}.{}", rdata[0], rdata[1], rdata[2], rdata[3]))
        }
        QType::AAAA if rdlen == 16 => {
            // Компактный IPv6
            let groups: Vec<String> = rdata.chunks(2)
                .map(|c| format!("{:x}", u16::from_be_bytes([c[0], c[1]])))
                .collect();
            Some(groups.join(":"))
        }
        _ => None,
    };

    let parsed_name = match &qtype {
        QType::CNAME | QType::NS | QType::PTR => {
            decode_name(data, rdata_start).map(|(n, _)| n)
        }
        _ => None,
    };

    Some((DnsRecord {
        name,
        rtype: qtype,
        rclass,
        ttl,
        rdata,
        parsed_addr,
        parsed_name,
    }, rdata_start + rdlen))
}

fn parse_edns(record: &DnsRecord) -> Option<EdnsInfo> {
    if record.rtype != QType::OPT { return None; }
    // OPT record: rclass = UDP payload size, ttl = ext_rcode | version | flags
    let udp_payload_size = record.rclass;
    // TTL в OPT: [ext_rcode(8)] [version(8)] [flags(16)]
    let ext_rcode  = (record.ttl >> 24) as u8;
    let version    = ((record.ttl >> 16) & 0xFF) as u8;
    let do_bit     = (record.ttl & 0x8000) != 0;
    Some(EdnsInfo {
        udp_payload_size,
        ext_rcode,
        version,
        dnssec_ok: do_bit,
    })
}

// ─── Главная функция парсинга ────────────────────────────────────────────────

/// Парсим DNS пакет из UDP payload (или TCP payload без 2-байтового префикса)
pub fn parse_dns(data: &[u8]) -> Option<DnsPacket> {
    // Минимальный DNS заголовок — 12 байт
    if data.len() < 12 { return None; }

    let txid    = u16::from_be_bytes([data[0], data[1]]);
    let flags   = u16::from_be_bytes([data[2], data[3]]);
    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
    let nscount = u16::from_be_bytes([data[8], data[9]]) as usize;
    let arcount = u16::from_be_bytes([data[10], data[11]]) as usize;

    let is_response = (flags & 0x8000) != 0;
    let opcode      = ((flags >> 11) & 0x0F) as u8;
    let aa          = (flags & 0x0400) != 0;
    let truncated   = (flags & 0x0200) != 0;
    let rd          = (flags & 0x0100) != 0;
    let ra          = (flags & 0x0080) != 0;
    let rcode       = RCode::from_u8((flags & 0x000F) as u8);

    // Sanity check: не парсим мусор
    // qdcount обычно 1; если вдруг > 10 — скорее всего не DNS
    if qdcount > 10 || ancount > 500 || nscount > 100 || arcount > 100 {
        return None;
    }

    let mut pos = 12usize;
    let mut questions  = Vec::with_capacity(qdcount);
    let mut answers    = Vec::with_capacity(ancount);
    let mut authority  = Vec::with_capacity(nscount);
    let mut additional = Vec::new();
    let mut edns       = None;

    // Questions
    for _ in 0..qdcount {
        let (q, next) = parse_question(data, pos)?;
        questions.push(q);
        pos = next;
    }

    // Answers
    for _ in 0..ancount {
        let (r, next) = parse_record(data, pos)?;
        answers.push(r);
        pos = next;
    }

    // Authority
    for _ in 0..nscount {
        let (r, next) = parse_record(data, pos)?;
        authority.push(r);
        pos = next;
    }

    // Additional (включая OPT/EDNS0)
    for _ in 0..arcount {
        let (r, next) = parse_record(data, pos)?;
        if r.rtype == QType::OPT {
            edns = parse_edns(&r);
        } else {
            additional.push(r);
        }
        pos = next;
    }

    Some(DnsPacket {
        txid,
        is_response,
        opcode,
        aa,
        truncated,
        rd,
        ra,
        rcode,
        questions,
        answers,
        authority,
        additional,
        edns,
    })
}

/// Парсим DNS из TCP payload.
/// TCP DNS имеет 2-байтовый length prefix (RFC 1035 §4.2.2)
pub fn parse_dns_tcp(data: &[u8]) -> Option<DnsPacket> {
    if data.len() < 2 { return None; }
    let msg_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + msg_len { return None; }
    parse_dns(&data[2..2 + msg_len])
}
