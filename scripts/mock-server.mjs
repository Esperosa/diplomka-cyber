// Maketa API pro vyvoj a testy UI. Data vychazeji z tests/golden/full_visibility_stack.json
// (skutecny tvar RunReport), doplnena o nove endpointy (zasahy, audit, vysledky overovani).
// NIKDY se nepouziva v produkci - UI samo zadna mock data neobsahuje.
//
//   node scripts/mock-server.mjs [port]     (vychozi port 8787)
//   MOCK_ROLE=analyst   -> approve/reject vraci 403 (test oprávnění)
//   MOCK_AUTH=1         -> vyzaduje Authorization: Bearer test
//   MOCK_RUNNING=1      -> autopilot behi (test tlacitka Zastavit)
//   MOCK_EMPTY=1        -> server bez bezu a bez novych endpointu (404)

import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(fileURLToPath(new URL(".", import.meta.url)), "..");
const uiDir = join(root, "ui");
const port = Number(process.argv[2] ?? process.env.PORT ?? 8787);
const ROLE = process.env.MOCK_ROLE ?? "operator";
const AUTH = process.env.MOCK_AUTH === "1";
const EMPTY = process.env.MOCK_EMPTY === "1";

const golden = JSON.parse(await readFile(join(root, "tests/golden/full_visibility_stack.json"), "utf8"));

const CLEAN_TEXT = {
  connection_timeout_burst: ["Pasivní vrstva zachytila opakované timeouty a retry stavy, které často doprovází přetížení nebo agresivní skenovací vzor.", "Prověřit limity služby, fronty a firewall. Při útoku dočasně zpřísnit rate limit."],
  default: ["Nález vznikl z korelace pasivních událostí a aktivního inventáře.", "Ověřit nález na stanici a rozhodnout o dalším kroku."],
};
const fix = (text, type, index) => (typeof text === "string" && text.includes("�") ? (CLEAN_TEXT[type] ?? CLEAN_TEXT.default)[index] : text);

function cleanReport(report) {
  const r = structuredClone(report);
  for (const f of r.findings) {
    f.rationale = fix(f.rationale, f.finding_type, 0);
    f.recommendation = fix(f.recommendation, f.finding_type, 1);
    f.evidence = f.evidence.map((e) => (e.includes("�") ? e.replace(/�+/g, "") : e));
    f.title = fix(f.title, f.finding_type, 0);
  }
  for (const t of r.triageActions ?? []) {
    t.rationale = fix(t.rationale, "default", 0);
    t.title = fix(t.title, "default", 0);
  }
  return r;
}

function baseReport(id, nazev, minutesAgo) {
  const r = cleanReport(golden);
  const now = Date.now() - minutesAgo * 60000;
  r.run.run_id = id;
  r.run.nazev = nazev;
  r.run.started_at = new Date(now - 7 * 60000).toISOString();
  r.run.finished_at = new Date(now).toISOString();
  r.summary.mas_parallelism_ratio = 0.78;
  r.summary.mas_queue_wait_ms_avg = 41.2;
  r.summary.mas_agent_sla_ratio = 0.94;
  r.verification_results = [
    { hypothesis_type: "high_risk_cve_exposure", method: "cve_intel_relookup", asset: "192.168.56.10", status: "executed", outcome: "2 CVE potvrzeno v KEV", runtime_ms: 412 },
    { hypothesis_type: "high_risk_cve_exposure", method: "cve_intel_relookup", asset: "192.168.56.10", status: "reused", outcome: "převzato z dřívější kontroly", runtime_ms: 0 },
    { hypothesis_type: "http_basic_without_tls", method: "read_only_content_inspection", asset: "192.168.56.20", status: "executed", outcome: "přihlašovací formulář bez TLS", runtime_ms: 1380 },
    { hypothesis_type: "correlation_uncertainty", method: "nmap_targeted_followup", asset: "192.168.56.30", status: "needs_approval", outcome: null, runtime_ms: null },
    { hypothesis_type: "unexpected_traffic", method: "passive_extended_observation", asset: "203.0.113.50", status: "skipped_out_of_scope", outcome: null, runtime_ms: null },
  ];
  return r;
}

// Rozsahly bezr pro test rozlozeni pole (14 stanic).
function largeReport(id, nazev, minutesAgo) {
  const r = baseReport(id, nazev, minutesAgo);
  const templates = r.hosts;
  const findings = [];
  const hypotheses = [];
  const hosts = [];
  for (let i = 0; i < 14; i += 1) {
    const t = structuredClone(templates[i % templates.length]);
    const ip = `192.168.56.${40 + i * 3}`;
    t.ip = ip;
    t.host_key = ip;
    t.host_id = `host:${ip}`;
    t.asset_id = `asset:${100 + i}`;
    t.hostname = ["web", "db", "cache", "vpn", "nas", "print", "iot", "cam", "ap", "mail", "git", "ci", "dns", "bak"][i] + `-${i + 1}`;
    t.services = t.services.slice(0, 1 + (i % 3)).map((s) => ({ ...s, service_key: `${ip}/${s.proto}/${s.port}`, service_id: `svc:${ip}/${s.proto}/${s.port}`, cves: i % 4 === 0 ? s.cves : i % 4 === 1 ? s.cves.slice(0, 1) : [] }));
    hosts.push(t);
    const source = r.findings.filter((f) => f.host_key === templates[i % templates.length].host_key);
    source.forEach((f, k) => {
      if (k > 1 && i % 2) return;
      const nf = structuredClone(f);
      nf.host_key = ip;
      nf.finding_id = `${f.finding_id}:${i}`;
      nf.severity = i % 5 === 0 ? "high" : i % 3 === 0 ? "medium" : f.severity;
      findings.push(nf);
      const hyp = r.hypotheses.find((h) => h.hypothesis_type === f.finding_type) ?? r.hypotheses[0];
      const nh = structuredClone(hyp);
      nh.affected_assets = [ip];
      hypotheses.push(nh);
    });
  }
  r.hosts = hosts;
  r.findings = findings;
  r.hypotheses = hypotheses;
  r.verification_plans = hypotheses.slice(0, 18).map((h, i) => {
    const base = structuredClone(r.verification_plans[i % r.verification_plans.length]);
    base.in_scope_assets = h.affected_assets;
    base.hypothesis_type = h.hypothesis_type;
    if (i % 7 === 3) base.excluded_out_of_scope = ["203.0.113.50"];
    return base;
  });
  return r;
}

// Ukazkova sit pro prohlidku mapy: 4 VLAN (10 sprava, 20 servery, 30 IoT, 40 uzivatele), ~100 zarizeni,
// switche, AP, tiskarny, kamery, wifi klienti, topologyEdges (LLDP, klient-AP, ARP) a cesta skoku agenta.
function showcaseReport(id, nazev, minutesAgo) {
  const r = baseReport(id, nazev, minutesAgo);
  const templates = r.hosts;
  const baseSvc = templates[0].services[0];
  const cveA = baseSvc.cves[0];
  const cveB = baseSvc.cves[1];
  const svc = (ip, port, name, product = null, version = null, o = {}) => {
    const s = structuredClone(baseSvc);
    Object.assign(s, { service_id: `svc:${ip}/tcp/${port}`, service_key: `${ip}/tcp/${port}`, port, proto: "tcp", port_state: "open", cpe: [], cves: o.cves ?? [], events: o.events ?? [], score: o.score ?? 1.2, priorita: o.prio ?? "nizka" });
    s.inventory = { ...s.inventory, service_name: name, product, version };
    return s;
  };
  const ev = (ip, port, type, message, severity, count, source) => ({
    correlation: { confidence: "high", host_id: `host:${ip}`, method: "ip+port", service_id: `svc:${ip}/tcp/${port}`, time_window_s: 3600 },
    event: { count, dst_ip: ip, dst_port: port, event_type: type, message, severity, source },
  });

  const A = { gw: "a:gw", core: "a:sw-core", s1: "a:sw-pat1", s2: "a:sw-pat2", ap1: "a:ap1", ap2: "a:ap2", ap3: "a:ap3", ap4: "a:ap4" };
  const defs = [];
  const add = (d) => defs.push(d);
  // ---- VLAN 10 sprava ----
  add({ ip: "10.20.1.1", name: "gw-brana", vlan: 10, vend: "Fortinet", asset: ["router", "FortiGate 60F", "librenms", A.gw], svcs: [[443, "https", "FortiOS"], [22, "ssh", "OpenSSH"]] });
  add({ ip: "10.20.1.2", name: "sw-core", vlan: 10, vend: "Cisco", mac: "00:1b:54:aa:00:02", asset: ["switch", "Catalyst 9300-24T", "librenms", A.core], svcs: [[22, "ssh", "Cisco SSH"], [161, "snmp"]] });
  add({ ip: "10.20.1.3", name: "sw-patro1", vlan: 10, vend: "Cisco", mac: "00:1b:54:aa:00:03", asset: ["switch", "Catalyst 1000-48P", "librenms", A.s1], svcs: [[22, "ssh", "Cisco SSH"]] });
  add({ ip: "10.20.1.4", name: "sw-patro2", vlan: 10, vend: "Cisco", mac: "00:1b:54:aa:00:04", asset: ["switch", "Catalyst 1000-48P", "librenms", A.s2], svcs: [[22, "ssh", "Cisco SSH"]] });
  [["10.20.1.11", "ap-kancelar-1", "Aruba", "AP-515", A.ap1], ["10.20.1.12", "ap-kancelar-2", "Aruba", "AP-515", A.ap2], ["10.20.1.13", "ap-sklad", "Ubiquiti", "U6-Pro", A.ap3], ["10.20.1.14", "ap-recepce", "Ubiquiti", "U6-Lite", A.ap4]].forEach(([ip, name, vend, model, aid], i) =>
    add({ ip, name, vlan: 10, vend, mac: `22:33:44:55:66:0${i + 1}`, asset: ["access-point", model, vend === "Aruba" ? "aruba" : "unifi", aid], svcs: [[22, "ssh", "Dropbear sshd"], [443, "https"]] }),
  );
  add({ ip: "10.20.1.20", name: "ntp-sprava", vlan: 10, svcs: [[22, "ssh", "OpenSSH", "8.9"], [123, "ntp"]], via: "core" });
  add({ ip: "10.20.1.22", name: "mon-zabbix", vlan: 10, svcs: [[443, "https", "nginx", "1.22"], [80, "http", "nginx", "1.22"], [10050, "zabbix-agent"]], via: "core", flag: "medium" });
  add({ ip: "10.20.1.30", name: null, vlan: 10, vend: "Dell", mac: "f8:bc:12:00:30:30", svcs: [[1812, "radius"]], via: "core" });
  // ---- VLAN 20 servery ----
  [["10.20.2.10", "srv-web01", [[443, "https", "nginx", "1.18.0"], [80, "http", "nginx", "1.18.0"]], "medium"], ["10.20.2.11", "srv-web02", [[443, "https", "nginx", "1.24.0"]]], ["10.20.2.12", "srv-mail", [[25, "smtp", "Postfix"], [587, "submission", "Postfix"], [993, "imaps", "Dovecot"]]], ["10.20.2.13", "srv-db01", [[5432, "postgresql", "PostgreSQL", "14.9"]]], ["10.20.2.14", "srv-db02", [[3306, "mysql", "MySQL", "5.7.33"]], "medium"], ["10.20.2.16", "srv-files", [[445, "microsoft-ds", "Samba", "4.13"], [139, "netbios-ssn", "Samba"], [2049, "nfs"]], "medium"], ["10.20.2.17", "srv-bak", [[445, "microsoft-ds", "Samba"], [22, "ssh", "OpenSSH"]]], ["10.20.2.18", "srv-dns", [[53, "domain", "dnsmasq", "2.89"]]], ["10.20.2.19", "srv-erp", [[8443, "https-alt", "Tomcat", "9.0.31"], [5432, "postgresql", "PostgreSQL"]], "high"], ["10.20.2.21", "srv-git", [[22, "ssh", "OpenSSH"], [8080, "http-proxy", "Gitea"]]], ["10.20.2.22", "srv-ci", [[8080, "http", "Jenkins", "2.346"]], "medium"], ["10.20.2.23", "srv-ldap", [[389, "ldap", "OpenLDAP"], [636, "ldaps"]]], ["10.20.2.24", "srv-vpn", [[1194, "openvpn", "OpenVPN", "2.5"]]], ["10.20.2.25", "srv-wiki", [[443, "https", "nginx"]]]].forEach(([ip, name, s, flag]) => add({ ip, name, vlan: 20, svcs: s, via: "core", flag }));
  // ---- VLAN 30 IoT ----
  ["vchod", "sklad", "parkoviste", "dvur", "chodba-1", "chodba-2", "dilna", "vrata"].forEach((n, i) =>
    add({ ip: `10.20.3.${21 + i}`, name: `cam-${n}`, vlan: 30, vend: i % 2 ? "Axis" : "Hikvision", mac: `bc:ad:28:00:00:${10 + i}`, svcs: [[554, "rtsp", i % 2 ? "Axis RTSP" : "Hikvision live555"], [80, "http", "GoAhead-Webs"]], via: i < 4 ? "s1" : "s2", asset: i % 3 === 0 ? ["camera", i % 2 ? "P3265-LVE" : "DS-2CD2143", "librenms", `a:cam${i}`] : null }),
  );
  add({ ip: "10.20.3.30", name: "nvr-01", vlan: 30, vend: "Hikvision", svcs: [[554, "rtsp", "Hikvision live555"], [8000, "http", "Hikvision NVR"]], via: "s1" });
  add({ ip: "10.20.3.31", name: "cam-sklad-2", vlan: 30, vend: "Hikvision", mac: "bc:ad:28:00:00:31", svcs: [[554, "rtsp", "Hikvision live555"], [80, "http", "GoAhead-Webs"]], via: "s2", flag: "high", suspicious: true });
  add({ ip: "10.20.3.40", name: "iot-brana-1", vlan: 30, vend: "Espressif", svcs: [[1883, "mqtt", "Mosquitto", "1.6.9"]], via: "s2", flag: "high" });
  ["recepce", "kancelar", "sklad", "obchod", "ucetni", null].forEach((n, i) =>
    add({ ip: `10.20.3.${50 + i}`, name: n ? `tisk-${n}` : null, vlan: 30, vend: ["HP", "Brother", "Canon", "Xerox", "Ricoh", "Epson"][i], mac: `3c:2a:f4:00:00:${50 + i}`, svcs: i % 2 ? [[9100, "jetdirect"]] : [[9100, "jetdirect", "HP JetDirect"], [631, "ipp", "CUPS"], [80, "http"]], via: i < 3 ? "s1" : "s2", asset: i === 0 ? ["printer", "LaserJet M507", "librenms", "a:pr0"] : null, flag: i === 2 ? "medium" : null }),
  );
  ["hvac-1", "hvac-2", "plc-vzduchotechnika", "hmi-vyroba"].forEach((n, i) =>
    add({ ip: `10.20.3.${60 + i}`, name: n, vlan: 30, svcs: i === 2 ? [[502, "modbus"]] : i === 3 ? [[80, "http"], [502, "modbus"]] : [[1883, "mqtt"], [80, "http", "Boa"]], via: "s2" }),
  );
  add({ ip: "10.20.3.70", name: null, vlan: 30, vend: "Espressif", mac: "24:6f:28:00:70:70", svcs: [], via: "s1" });
  add({ ip: "10.20.3.71", name: null, vlan: 30, mac: "ac:cf:23:00:71:71", svcs: [], via: "s2" });
  [["10.20.3.80", "senzor-sklad-1", 3], ["10.20.3.81", "senzor-sklad-2", 3], ["10.20.3.82", "senzor-dilna", 4]].forEach(([ip, name, ap]) => add({ ip, name, vlan: 30, vend: "Espressif", asset: ["wireless-client", null, "unifi", `a:wi${ip}`], wifi: { ap: A[`ap${ap}`], ssid: "IoT-WiFi" }, svcs: [] }));
  // ---- VLAN 40 uzivatele ----
  for (let i = 0; i < 16; i += 1) add({ ip: `10.20.4.${101 + i}`, name: `ws-${String(i + 1).padStart(2, "0")}`, vlan: 40, vend: ["Dell", "HP", "Lenovo"][i % 3], svcs: i % 4 === 0 ? [[3389, "ms-wbt-server"], [445, "microsoft-ds"]] : [[445, "microsoft-ds"]], via: i < 8 ? "s1" : "s2", flag: i === 5 ? "medium" : null });
  for (let i = 0; i < 8; i += 1) add({ ip: `10.20.4.${131 + i}`, name: `nb-${String(i + 1).padStart(2, "0")}`, vlan: 40, vend: ["Lenovo", "Apple", "Dell"][i % 3], svcs: [], wifi: { ap: A[`ap${(i % 2) + 1}`], ssid: "Firma-WiFi" }, asset: ["wireless-client", null, "aruba", `a:nb${i}`] });
  for (let i = 0; i < 8; i += 1) add({ ip: `10.20.4.${151 + i}`, name: `tel-${i + 1}`, vlan: 40, vend: i % 2 ? "Yealink" : "Cisco", svcs: [[5060, "sip"]], via: i < 4 ? "s1" : "s2" });
  for (let i = 0; i < 14; i += 1) add({ ip: `10.20.4.${171 + i}`, name: `${["iphone", "galaxy", "pixel", "ipad"][i % 4]}-${i + 1}`, vlan: 40, vend: ["Apple", "Samsung", "Google", "Apple"][i % 4], mac: `aa:00:bb:11:cc:${(10 + i).toString(16)}`, asset: ["wireless-client", null, "aruba", `a:wc${i}`], wifi: { ap: A[`ap${(i % 4) + 1}`], ssid: "Firma-WiFi" }, svcs: [] });
  [190, 191, 192].forEach((o, i) => add({ ip: `10.20.4.${o}`, name: null, vlan: 40, mac: `d8:00:00:00:${o.toString(16)}:01`, svcs: i === 2 ? [[22, "ssh", "OpenSSH"]] : [], via: "s1" }));

  const swOf = { core: A.core, s1: A.s1, s2: A.s2 };
  const hosts = [];
  const findings = [];
  const hypotheses = [];
  const assets = [];
  const edges = [];
  const mkEdge = (rel, a, b, details, source = "librenms") => edges.push({ edge_id: `edge:${source}:${rel}:${a}:${b}`, relation: rel, source, source_asset_id: a, target_asset_id: b, confidence: "high", details });
  const vlanName = { 10: "Správa", 20: "Servery", 30: "IoT", 40: "Uživatelé" };
  let port = 1;
  defs.forEach((d, counter) => {
    const ip = d.ip;
    const t = structuredClone(templates[counter % templates.length]);
    const sev = d.flag;
    const services = d.svcs.map(([p, name, product, version], k) => {
      const withCve = sev === "high" && k === 0;
      const events = d.suspicious && k === 0 ? [ev(ip, p, "unexpected_traffic", "Odchozí spojení na 198.51.100.7:4444 z kamery, která jinak komunikuje jen s NVR.", "high", 6, "suricata+zeek")] : sev && k === 0 ? [ev(ip, p, "connection_timeout_burst", "Spojení vykazuje timeout/retry tlak.", sev === "high" ? "high" : "medium", 4 + (counter % 5), "zeek")] : [];
      return svc(ip, p, name, product ?? null, version ?? null, { cves: withCve ? [cveA, cveB] : sev === "medium" && k === 0 && counter % 2 ? [cveA] : [], events, score: withCve ? 11.2 : 1.2, prio: withCve ? "vysoka" : "nizka" });
    });
    hosts.push({ ...t, asset_id: `asset:${100 + counter}`, host_id: `host:${ip}`, host_key: ip, ip, hostname: d.name, mac: d.mac ?? null, vendor: d.vend ?? null, identity_note: null, services });
    if (sev) {
      const source = r.findings.filter((f) => f.host_key === templates[counter % templates.length].host_key);
      (source.length ? source : r.findings.slice(0, 1)).slice(0, 2).forEach((f, k) => {
        const nf = structuredClone(f);
        nf.host_key = ip;
        nf.finding_id = `${f.finding_id}:${counter}:${k}`;
        nf.severity = k === 0 ? sev : "low";
        findings.push(nf);
        const hyp = structuredClone(r.hypotheses.find((h) => h.hypothesis_type === f.finding_type) ?? r.hypotheses[0]);
        hyp.affected_assets = [ip];
        hypotheses.push(hyp);
      });
    }
    // aktivum + vazby
    const aid = d.asset ? d.asset[3] : `a:${ip}`;
    const type = d.asset ? d.asset[0] : d.svcs.length || d.name ? "endpoint" : "unknown";
    assets.push({ asset_id: aid, asset_type: type, name: d.name ?? `neznámé ${ip}`, source: d.asset ? d.asset[2] : "librenms", confidence: "high", ip, mac: d.mac ?? null, vendor: d.vend ?? null, model: d.asset ? d.asset[1] : null, status: "up", location: d.wifi ? d.wifi.ssid : null, linked_host_key: ip, observations: [], serial: null });
    const vd = [`vlan=${d.vlan}`, `vlan_name=${vlanName[d.vlan]}`];
    if (d.wifi) mkEdge("client_of", aid, d.wifi.ap, [`ssid=${d.wifi.ssid}`, ...vd], "aruba");
    else if (d.via) mkEdge("arp_seen", swOf[d.via], aid, [`port=Gi1/0/${port++}`, ...vd]);
  });
  const L = (a, b, pa, pb) => mkEdge("lldp", a, b, [`local_port=${pa}`, `remote_port=${pb}`, "protocol=lldp"]);
  L(A.gw, A.core, "Gi0/0/1", "Gi1/0/48");
  L(A.core, A.s1, "Gi1/0/1", "Gi1/0/52");
  L(A.core, A.s2, "Gi1/0/2", "Gi1/0/52");
  L(A.s1, A.ap1, "Gi1/0/3", "eth0");
  L(A.s1, A.ap2, "Gi1/0/4", "eth0");
  L(A.s2, A.ap3, "Gi1/0/3", "eth0");
  L(A.s2, A.ap4, "Gi1/0/4", "eth0");
  r.hosts = hosts;
  r.findings = findings;
  r.hypotheses = hypotheses;
  r.networkAssets = assets;
  r.topologyEdges = edges;
  // Provoz mezi zarizenimi (ukazkova data pro volitelne pole trafficEdges; skutecny backend je zatim neposila).
  // Deterministicke dvojice, objem s tezkym ocasem: par silnych toku, mnoho slabych.
  r.trafficEdges = hosts.flatMap((h, i) => {
    const out = [];
    for (const k of [3, 11, 29]) {
      const j = (i * 7 + k) % hosts.length;
      if (j === i) continue;
      const w = Math.pow(((i * 37 + k * 13) % 100) / 100, 3);
      out.push({ src: h.ip, dst: hosts[j].ip, bytes: Math.round(2e4 + w * 9e8), flows: 1 + Math.round(w * 400), protocol: [443, 445, 53, 22, 5432][(i + k) % 5] });
    }
    return out;
  });
  r.verification_plans = hypotheses.slice(0, 12).map((h, i) => {
    const base = structuredClone(r.verification_plans[i % r.verification_plans.length]);
    base.in_scope_assets = h.affected_assets;
    base.hypothesis_type = h.hypothesis_type;
    return base;
  });
  // cesta skoku: podezrely uzel -> sousedni zarizeni -> server -> (schvaleni) -> mimo rozsah
  r.verification_results = [
    { hypothesis_type: "unexpected_traffic", method: "passive_extended_observation", asset: "10.20.3.31", status: "executed", outcome: "odchozí spojení na 198.51.100.7:4444", runtime_ms: 640 },
    { hypothesis_type: "multi_target_pattern", method: "read_only_content_inspection", asset: "10.20.3.40", status: "executed", outcome: "stejný vzor, druhý uzel ve stejné podsíti", runtime_ms: 910 },
    { hypothesis_type: "lateral_movement", method: "cve_intel_relookup", asset: "10.20.2.16", status: "executed", outcome: "SMB relace z 10.20.3.40", runtime_ms: 388 },
    { hypothesis_type: "lateral_movement", method: "nmap_targeted_followup", asset: "10.20.2.19", status: "needs_approval", outcome: null, runtime_ms: null },
    { hypothesis_type: "high_risk_cve_exposure", method: "cve_intel_relookup", asset: "10.20.1.22", status: "reused", outcome: "převzato z dřívější kontroly", runtime_ms: 0 },
    { hypothesis_type: "unexpected_traffic", method: "passive_extended_observation", asset: "198.51.100.7", status: "skipped_out_of_scope", outcome: null, runtime_ms: null },
  ];
  r.summary.hosts_total = hosts.length;
  r.summary.services_total = hosts.reduce((n, h) => n + h.services.length, 0);
  r.summary.events_total = 1284;
  r.summary.realtime_sources_total = 3;
  r.summary.wireless_clients_total = assets.filter((a) => a.asset_type === "wireless-client").length;
  r.summary.topology_edges_total = edges.length;
  return r;
}


// Velka sit (jen MOCK_BIG=1): ukazkova sit 3x zkopirovana do dalsich rozsahu, ~300 zarizeni, pro mereni vykonu mapy.
function bigReport(id, nazev, minutesAgo) {
  const r = showcaseReport(id, nazev, minutesAgo);
  const hosts = [...r.hosts];
  const findings = [...r.findings];
  for (const copy of [1, 2]) {
    for (const h of r.hosts) {
      const ip = h.ip.replace(/^10\.20\./, `10.2${copy}.`);
      const c = structuredClone(h);
      Object.assign(c, { ip, host_key: ip, host_id: `host:${ip}`, asset_id: `${h.asset_id}:${copy}`, hostname: h.hostname ? `${h.hostname}-${copy}` : null });
      c.services = c.services.map((sv) => ({ ...sv, service_id: sv.service_id.replace("10.20.", `10.2${copy}.`), service_key: sv.service_key.replace("10.20.", `10.2${copy}.`), events: [] }));
      hosts.push(c);
    }
    for (const f of r.findings.slice(0, 6)) findings.push({ ...structuredClone(f), finding_id: `${f.finding_id}:c${copy}`, host_key: f.host_key.replace(/^10\.20\./, `10.2${copy}.`) });
  }
  r.hosts = hosts;
  r.findings = findings;
  r.networkAssets = r.networkAssets.slice(0, 20);
  r.summary.hosts_total = hosts.length;
  return r;
}

const ALL_RUNS = [
  { id: "run-20261031130000-1-sit", nazev: "Ukázková síť: 4 VLAN, switche, AP, cesta skoků", build: () => showcaseReport("run-20261031130000-1-sit", "Ukázková síť: 4 VLAN, switche, AP, cesta skoků", 2) },
  { id: "run-20261031120000-1-demo", nazev: "Full visibility stack", build: () => baseReport("run-20261031120000-1-demo", "Full visibility stack", 6) },
  { id: "run-20261031090000-1-large", nazev: "Rozsáhlá síť (ukázka, 14 stanic)", build: () => largeReport("run-20261031090000-1-large", "Rozsáhlá síť (ukázka, 14 stanic)", 190) },
];

// Ukazkova sit je nejnovejsi jen s MOCK_SHOWCASE=1; testy pocitaji s malym demo behem jako vychozim.
if (process.env.MOCK_BIG === "1") ALL_RUNS.unshift({ id: "run-20261031140000-1-big", nazev: "Velká síť (ukázka, ~300 zařízení)", build: () => bigReport("run-20261031140000-1-big", "Velká síť (ukázka, ~300 zařízení)", 1) });
const RUNS = process.env.MOCK_SHOWCASE === "1" || process.env.MOCK_BIG === "1" ? ALL_RUNS : [...ALL_RUNS.slice(1), ALL_RUNS[0]];

// ---------- stav zasahu ----------
const nowIso = () => new Date().toISOString();
let enforcementMode = process.env.MOCK_MODE ?? "dry_run";
let nextId = 4;
const actions = [
  { id: 1, ip: "203.0.113.50", ttl_seconds: 3600, reason: "Opakované skenování portů z vnější adresy", finding_id: null, status: "applied", nft_command: ["add", "element", "inet", "bakula", "blocked_ips", "{ 203.0.113.50 timeout 3600s }"], proposed_at: new Date(Date.now() - 22 * 60000).toISOString(), decided_by: "operator", decided_at: new Date(Date.now() - 20 * 60000).toISOString(), applied_at: new Date(Date.now() - 20 * 60000).toISOString() },
  { id: 2, ip: "198.51.100.7", ttl_seconds: 900, reason: "Podezřelý C2 provoz na 4444/tcp", finding_id: golden.findings[0].finding_id, status: "proposed", nft_command: ["add", "element", "inet", "bakula", "blocked_ips", "{ 198.51.100.7 timeout 900s }"], proposed_at: new Date(Date.now() - 3 * 60000).toISOString(), decided_by: null, decided_at: null, applied_at: null },
  { id: 3, ip: "198.51.100.99", ttl_seconds: 600, reason: "Zkušební návrh", finding_id: null, status: "rejected", nft_command: ["add", "element", "inet", "bakula", "blocked_ips", "{ 198.51.100.99 timeout 600s }"], proposed_at: new Date(Date.now() - 90 * 60000).toISOString(), decided_by: "operator", decided_at: new Date(Date.now() - 85 * 60000).toISOString(), applied_at: null },
];
const audit = [
  { id: 1, at: new Date(Date.now() - 95 * 60000).toISOString(), actor: "analyst", action: "enforcement.proposed", subject: "198.51.100.99", detail: "ttl=600s" },
  { id: 2, at: new Date(Date.now() - 85 * 60000).toISOString(), actor: "operator", action: "enforcement.rejected_by_operator", subject: "#3", detail: "zamítnuto" },
  { id: 3, at: new Date(Date.now() - 22 * 60000).toISOString(), actor: "analyst", action: "enforcement.proposed", subject: "203.0.113.50", detail: "ttl=3600s" },
  { id: 4, at: new Date(Date.now() - 20 * 60000).toISOString(), actor: "operator", action: "enforcement.approved", subject: "#1", detail: "schváleno" },
  { id: 5, at: new Date(Date.now() - 3 * 60000).toISOString(), actor: "analyst", action: "enforcement.proposed", subject: "198.51.100.7", detail: "ttl=900s" },
].reverse();

const PROTECTED = [/^127\./, /^169\.254\./, /^22[4-9]\.|^23\d\./, /^192\.168\.56\.1$/];

// ---------- pomocne ----------
const send = (res, status, body, headers = {}) => {
  const payload = typeof body === "string" ? body : JSON.stringify(body);
  res.writeHead(status, { "content-type": typeof body === "string" ? "text/plain; charset=utf-8" : "application/json; charset=utf-8", "cache-control": "no-store", ...headers });
  res.end(payload);
};
const readBody = (req) => new Promise((resolve) => {
  let data = "";
  req.on("data", (c) => (data += c));
  req.on("end", () => { try { resolve(data ? JSON.parse(data) : {}); } catch { resolve({}); } });
});
const MIME = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8", ".json": "application/json", ".png": "image/png", ".svg": "image/svg+xml", ".woff2": "font/woff2", ".txt": "text/plain; charset=utf-8" };

const automationStatus = {
  state: "idle", current_cycle: 3, total_cycles: 3, progress_pct: 100, progress_ratio: 1, current_phase: "finalize", current_phase_label: "Dokončeno", message: "Poslední cyklus doběhl bez chyby.", latest_run_id: RUNS[0].id, process_running: process.env.MOCK_RUNNING === "1",
  phases: [
    { phase_id: "inventory", label: "Inventář služeb", status: "done", progress_pct: 100, summary: "" },
    { phase_id: "followup", label: "Cílený follow-up", status: "done", progress_pct: 100, summary: "" },
    { phase_id: "forensic", label: "Forenzní vrstva", status: "done", progress_pct: 100, summary: "" },
    { phase_id: "finalize", label: "Uzavření běhu", status: "done", progress_pct: 100, summary: "" },
  ],
  agents: [],
};

createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", `http://${req.headers.host}`);
  const path = url.pathname;
  try {
    if (path.startsWith("/api/")) return await api(req, res, url, path);
    let file = normalize(path === "/" ? "/index.html" : path).replace(/^(\.\.[/\\])+/, "");
    const data = await readFile(join(uiDir, file)).catch(() => null);
    if (!data) return send(res, 404, "Nenalezeno");
    res.writeHead(200, { "content-type": MIME[extname(file)] ?? "application/octet-stream", "cache-control": "no-store" });
    res.end(data);
  } catch (error) {
    send(res, 500, { error: String(error) });
  }
}).listen(port, "127.0.0.1", () => console.log(`Mock API + UI na http://127.0.0.1:${port}/ (role=${ROLE}, auth=${AUTH}, empty=${EMPTY})`));

async function api(req, res, url, path) {
  const method = req.method ?? "GET";
  if (AUTH && path !== "/api/meta" && req.headers.authorization !== "Bearer test") return send(res, 401, { error: "token" });
  if (method !== "GET" && req.headers["x-bakula-csrf"] !== "1") return send(res, 403, { error: "Chybí hlavička X-Bakula-Csrf." });

  if (path === "/api/meta") return send(res, 200, { auth_required: AUTH });
  if (path === "/api/runs") return send(res, 200, EMPTY ? [] : RUNS.map((run) => { const r = run.build(); return { run_id: run.id, nazev: run.nazev, hosts_total: r.hosts.length, services_total: r.hosts.reduce((n, h) => n + h.services.length, 0), cves_total: Number(r.summary.cves_total) }; }));
  const runMatch = path.match(/^\/api\/runs\/([^/]+)(?:\/(export|assistant)(?:\/(stream|json|md|txt))?)?$/);
  if (runMatch) {
    const run = RUNS.find((r) => r.id === decodeURIComponent(runMatch[1]));
    if (!run || EMPTY) return send(res, 404, { error: "run" });
    if (!runMatch[2]) return send(res, 200, run.build());
    if (runMatch[2] === "export") return send(res, 200, JSON.stringify(run.build()), { "content-disposition": `attachment; filename="${run.id}.${runMatch[3]}"` });
    if (runMatch[2] === "assistant") {
      const body = await readBody(req);
      const text = `K dotazu „${String(body.prompt ?? "").slice(0, 60)}“: nejdřív ověř službu s nejvyšším CVSS a teprve potom navrhuj zásah. Plán ověřování k tomu doporučuje čtecí kontrolu bez schválení.`;
      if (runMatch[3] === "stream") {
        res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-store" });
        for (const word of text.split(" ")) { res.write(`data: ${JSON.stringify({ type: "chunk", text: word + " " })}\n\n`); await new Promise((r) => setTimeout(r, 15)); }
        res.write(`data: ${JSON.stringify({ type: "done", mode: "mock", sources: ["finding"] })}\n\n`);
        return res.end();
      }
      return send(res, 200, { answer: text, mode: "mock", sources: [{ label: "finding" }] });
    }
  }
  if (path === "/api/verification/latest") return send(res, 200, EMPTY ? null : { summary: { total: 6, passed: 6, failed: 0 } });
  if (path === "/api/automation/status") return send(res, 200, EMPTY ? null : automationStatus);
  if (path === "/api/automation/latest") return send(res, 200, EMPTY ? null : {
    summary: { cycles_total: 3, tooling_coverage_ratio: 0.8, service_identity_coverage_ratio: 1, automation_agents_total: 22, automation_rounds_total: 3, forensic_targets_total: 3, mas_consensus_score: 0.65, mas_consensus_state: "review", run_ids: [RUNS[0].id] },
    agents: [], capabilities: [{ capability_id: "nmap", label: "Nmap inventář", available: true, activated: true }, { capability_id: "zeek", label: "Zeek pasivní senzor", available: true, activated: true }, { capability_id: "suricata", label: "Suricata alerty", available: true, activated: false }, { capability_id: "nuclei", label: "Nuclei šablony", available: false, activated: false }],
  });
  if (path === "/api/automation/restart") {
    if (automationStatus.process_running) return send(res, 409, "Autopilot už běží. Použij reset nebo počkej na dokončení.");
    automationStatus.process_running = true;
    return send(res, 200, { ok: true });
  }
  if (path === "/api/automation/reset") {
    automationStatus.process_running = false;
    return send(res, 200, { ok: true });
  }
  if (path === "/api/readiness") return send(res, 200, EMPTY ? null : { status: "partial", grade: "B", score: 78, blockers: ["Chybí produkční Zeek sensor"], next_steps: ["Připojit Zeek log adresář", "Zapnout API token"], checks: [{ check_id: "auth", label: "Autentizace API", status: "ok", score: 100, evidence: ["require_api_token=true"], next_step: "" }, { check_id: "passive", label: "Pasivní telemetrie", status: "warn", score: 40, evidence: ["zeek: nenalezeno"], next_step: "Připojit Zeek log adresář" }] });
  if (path === "/api/ai/status") return send(res, 200, { mode: "mock" });

  if (EMPTY && (path.startsWith("/api/enforcement") || path.startsWith("/api/audit"))) return send(res, 404, { error: "nenalezeno" });

  if (path === "/api/enforcement/actions") return send(res, 200, { mode: enforcementMode, actions });
  if (path === "/api/enforcement/propose" && method === "POST") {
    if (ROLE === "viewer") return send(res, 403, { error: "Forbidden" });
    const body = await readBody(req);
    const ip = String(body.ip ?? "");
    if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip) && !ip.includes(":")) return send(res, 422, { error: "UnparseableIp" });
    if (PROTECTED.some((re) => re.test(ip))) return send(res, 422, { error: "ProtectedRange" });
    if (!(body.ttl_seconds >= 1 && body.ttl_seconds <= 86400)) return send(res, 422, { error: "TtlExceedsMaximum" });
    if (actions.some((a) => a.ip === ip && ["proposed", "approved", "applied"].includes(a.status))) return send(res, 422, { error: "AlreadyActive" });
    const action = { id: nextId++, ip, ttl_seconds: body.ttl_seconds, reason: body.reason ?? "", finding_id: body.finding_id ?? null, status: "proposed", nft_command: ["add", "element", "inet", "bakula", "blocked_ips", `{ ${ip} timeout ${body.ttl_seconds}s }`], proposed_at: nowIso(), decided_by: null, decided_at: null, applied_at: null };
    actions.push(action);
    audit.unshift({ id: audit.length + 1, at: nowIso(), actor: ROLE, action: "enforcement.proposed", subject: ip, detail: `ttl=${body.ttl_seconds}s` });
    return send(res, 200, action);
  }
  const decide = path.match(/^\/api\/enforcement\/(\d+)\/(approve|reject)$/);
  if (decide && method === "POST") {
    if (ROLE !== "operator" && ROLE !== "admin") return send(res, 403, { error: "Forbidden" });
    const action = actions.find((a) => a.id === Number(decide[1]));
    if (!action) return send(res, 404, { error: "action" });
    action.status = decide[2] === "approve" ? (enforcementMode === "enforce" ? "applied" : "approved") : "rejected";
    action.decided_by = ROLE;
    action.decided_at = nowIso();
    if (action.status === "applied") action.applied_at = nowIso();
    audit.unshift({ id: audit.length + 1, at: nowIso(), actor: ROLE, action: (decide[2] === "approve" ? "enforcement.approved" : "enforcement.rejected_by_operator"), subject: `#${action.id}`, detail: decide[2] === "approve" ? "schváleno" : "zamítnuto" });
    return send(res, 200, action);
  }
  if (path === "/api/audit") return send(res, 200, audit.slice(0, Number(url.searchParams.get("limit") ?? 100)));
  if (path === "/api/audit/verify") return send(res, 200, { chain_ok: process.env.MOCK_CHAIN_BAD !== "1" });
  return send(res, 404, { error: "nenalezeno" });
}
