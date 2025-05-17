#!/bin/bash

# Modo estricto y IFS seguro
set -euo pipefail
IFS=$'\n\t'

# COLORES
RED='\e[1;91m'; GREEN='\e[1;92m'; YELLOW='\e[1;93m'; CYAN='\e[1;96m'; WHITE='\e[1;97m'; BOLD='\e[1m'; NC='\e[0m'

# API KEY (no cambiar)
ABUSEIPDB_API_KEY="c3107b7e9b3eedf8a54abe0c2bf2a32ba1379afec1467520a757f17259139331136ae37844dad5c4"

# Verificar dependencias
for cmd in curl jq dig whois nmap; do
  command -v "$cmd" >/dev/null 2>&1 || { echo -e "${RED}❌ Falta $cmd${NC}"; exit 1; }
done

# BLACKLISTS
declare -A blacklists=(
  ["zen.spamhaus.org"]="https://www.spamhaus.org/lookup/"
  ["pbl.spamhaus.org"]="https://www.spamhaus.org/pbl/removal/"
  ["sbl.spamhaus.org"]="https://www.spamhaus.org/sbl/removal/"
  ["xbl.spamhaus.org"]="https://www.spamhaus.org/xbl/"
  ["bl.spamcop.net"]="https://www.spamcop.net/bl.shtml"
  ["dnsbl.sorbs.net"]="https://www.sorbs.net/lookup.shtml"
  ["b.barracudacentral.org"]="https://www.barracudacentral.org/rbl/removal-request"
  ["dnsbl-1.uceprotect.net"]="https://www.uceprotect.net/en/index.php"
  ["psbl.surriel.com"]="https://psbl.org/"
)

reverse_ip() {
  echo "$1" | awk -F. '{print $4"."$3"."$2"."$1}'
}

get_geo() {
  curl -s "https://ipinfo.io/${1}/json" \
    | jq -r '.ip, .city, .region, .country, .org' \
    | paste -sd " | "
}

show_whois() {
  echo -e "\n${CYAN}🧾 WHOIS básico...${NC}"
  whois "$1" \
    | grep -Ei 'CIDR|NetName|OrgName|Country|abuse|contact|descr' \
    | uniq
}

check_dnsbls() {
  local ip="$1" rev_ip
  rev_ip=$(reverse_ip "$ip")
  DNSBL_TOTAL=0   # ahora global
  echo -e "\n${CYAN}🔍 Verificando DNSBLs...${NC}"
  for bl in "${!blacklists[@]}"; do
    if dig +short "${rev_ip}.${bl}" | grep -q .; then
      echo -e "${RED}[ENLISTADA]${NC} $bl"
      ((DNSBL_TOTAL++))
    else
      echo -e "${GREEN}[NO]${NC} $bl"
    fi
  done
}

check_abuseipdb() {
  local ip="$1"
  echo -e "\n${CYAN}📡 AbuseIPDB...${NC}"
  local resp
  resp=$(curl -sG https://api.abuseipdb.com/api/v2/check \
    --data-urlencode "ipAddress=$ip" \
    -d maxAgeInDays=90 \
    -H "Key: $ABUSEIPDB_API_KEY" \
    -H "Accept: application/json")

  ABUSE_SCORE=$(echo "$resp" | jq '.data.abuseConfidenceScore')
  ABUSE_REPORTS=$(echo "$resp" | jq '.data.totalReports')
  country=$(echo "$resp" | jq -r '.data.countryCode')
  usage=$(echo "$resp" | jq -r '.data.usageType')

  echo -e "País: $country\nUso: $usage\nScore: ${YELLOW}${ABUSE_SCORE}/100${NC}\nReportes: $ABUSE_REPORTS"
}

scan_ports() {
  echo -e "\n${CYAN}🔓 Escaneo puertos (top 20)...${NC}"
  PORTS=""
  # primer nmap con || true para no abortar por set -e
  nmap -Pn --top-ports 20 "$1" &>/dev/null || true
  PORTS=$(nmap -Pn --top-ports 20 "$1" \
    | grep -E '^[0-9]+/tcp' \
    | awk '{print $1}' \
    | paste -sd "," -)
}

clasifica_riesgo() {
  riesgo=0
  (( DNSBL_TOTAL>0 )) && ((riesgo++))
  (( ABUSE_SCORE>25 )) && ((riesgo++))
  [[ -n "${PORTS}" ]] && ((riesgo++))
  case $riesgo in 0) RISK="BAJO";; 1) RISK="MODERADO";; *) RISK="ALTO";; esac
}

recomienda() {
  echo -e "\n${WHITE}💡 Recomendación:${NC}"
  case $riesgo in
    0) echo -e "${GREEN}IP segura.${NC}";;
    1) echo -e "${YELLOW}Monitorea.${NC}";;
    *) echo -e "${RED}Bloquea y monitorea.${NC}";;
  esac
}

send_report() {
  local to="$1"
  local report="Informe IP $ip
Geoloc: $GEO_DATA
DNSBLs: $DNSBL_TOTAL
Abuse: $ABUSE_SCORE/100 ($ABUSE_REPORTS)
Puertos: ${PORTS:-Ninguno}
Riesgo: $RISK"
  if command -v mail >/dev/null; then
    echo -e "$report" | mail -s "Informe IP $ip" "$to"
    echo -e "${GREEN}✅ Enviado a $to${NC}"
  elif command -v sendmail >/dev/null; then
    { echo "To: $to"; echo "Subject: Informe IP $ip"; echo; echo "$report"; } | sendmail -t
    echo -e "${GREEN}✅ Enviado a $to${NC}"
  else
    echo -e "${YELLOW}⚠️ No hay cliente de correo. Informe:\n$report${NC}"
  fi
}

echo -e "${BOLD}${CYAN}=== ANALIZADOR DE IP ===${NC}"
read -p "🔎 IP: " ip
[[ ! $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && { echo -e "${RED}IP inválida${NC}"; exit 1; }
read -p "✉️  Email destino: " EMAIL

# inicializo globals
DNSBL_TOTAL=0; ABUSE_SCORE=0; ABUSE_REPORTS=0; PORTS=""

GEO_DATA=$(get_geo "$ip")
show_whois "$ip"
check_dnsbls "$ip"
check_abuseipdb "$ip"
scan_ports "$ip"

echo -e "\n${BOLD}=== RESUMEN ===${NC}
🌍 $GEO_DATA
📛 DNSBLs: $DNSBL_TOTAL
📊 Abuse: $ABUSE_SCORE/100 ($ABUSE_REPORTS)
🔓 Puertos: ${PORTS:-Ninguno}"

clasifica_riesgo
recomienda
send_report "$EMAIL"

echo -e "\n${BOLD}${GREEN}✅ Listo${NC}"
asdasdasd