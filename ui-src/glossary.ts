// Srozumitelne popisy metod a typu hypotez. Zdroj: katalog kandidatu v src/verification_planner.rs.
// Neznama hodnota se ukaze beze zmeny, nic se nedomysli.
export type MethodInfo = { label: string; does: string; touchesNetwork: boolean };

export const METHOD_INFO: Record<string, MethodInfo> = {
  passive_extended_observation: {
    label: "Delší pasivní pozorování",
    does: "Jen déle sleduje provoz, který už v síti probíhá. Nic nového na cíl neposílá.",
    touchesNetwork: false,
  },
  nmap_targeted_followup: {
    label: "Cílený aktivní sken (nmap)",
    does: "Pošle na cílovou stanici skriptovaný sken služeb (nmap -sV -sC). Je to aktivní kontrola nad úrovní čtení, cíl ji uvidí a může na ni reagovat.",
    touchesNetwork: true,
  },
  read_only_content_inspection: {
    label: "Čtecí kontrola obsahu",
    does: "Jeden čtecí HTTP dotaz na službu. Nic nezapisuje ani nemění.",
    touchesNetwork: true,
  },
  cve_intel_relookup: {
    label: "Nové vyhledání CVE",
    does: "Znovu se podívá do už stažené databáze zranitelností. Na cílovou síť se nesahá.",
    touchesNetwork: false,
  },
};

export function methodLabel(method: string): string {
  return METHOD_INFO[method]?.label ?? method.replace(/_/g, " ");
}

export const HYPOTHESIS_LABEL: Record<string, string> = {
  correlation_uncertainty: "Nejistá korelace událostí",
  identification_gap: "Neurčená identita služby",
  connection_timeout_burst: "Nárůst timeoutů a opakování",
  high_risk_cve_exposure: "Služba s vysoce rizikovým CVE",
  known_exploited_vulnerability: "Aktivně zneužívaná zranitelnost",
  probable_exploitation_interest: "Pravděpodobný zájem útočníků",
  management_surface_exposure: "Vystavené správcovské rozhraní",
  new_exposed_service: "Nově vystavená služba",
  plaintext_management_protocol: "Správa nešifrovaným protokolem",
  http_basic_without_tls: "HTTP Basic bez TLS",
  insecure_auth_possible: "Možné nezabezpečené přihlášení",
  lateral_movement: "Možný postranní pohyb",
  greenbone_finding: "Nález ze skenu Greenbone",
};

export function hypothesisLabel(type: string): string {
  return HYPOTHESIS_LABEL[type] ?? type.replace(/_/g, " ");
}

export const AUDIT_ACTION_LABEL: Record<string, string> = {
  "enforcement.proposed": "Zásah navržen",
  "enforcement.approved": "Zásah schválen",
  "enforcement.rejected_by_operator": "Zásah zamítnut operátorem",
  "enforcement.rejected": "Návrh zásahu odmítnut serverem",
  "enforcement.duplicate": "Duplicitní návrh odmítnut",
  "enforcement.dry_run": "Zkušební provedení (nic se neblokovalo)",
  "enforcement.applied": "Blok aplikován na bráně",
  "enforcement.failed": "Provedení zásahu selhalo",
  "enforcement.expired": "Blok vypršel a byl odstraněn",
  "enforcement.drift_removed": "Blok bez aktivního zásahu odstraněn z brány",
  "enforcement.drift_remove_failed": "Odstranění bloku bez aktivního zásahu selhalo",
  "enforcement.drift_missing": "Aktivní blok na bráně chybí",
  "finding.verdict": "Verdikt nálezu",
};

export function auditActionLabel(action: string): string {
  return AUDIT_ACTION_LABEL[action] ?? action;
}
