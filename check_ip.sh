#!/bin/bash
#Nicolas Saavedra
# ===================== COLORES =====================
RED='\e[1;91m';   GREEN='\e[1;92m'; YELLOW='\e[1;93m'
CYAN='\e[1;96m';  WHITE='\e[1;97m';  BOLD='\e[1m'; NC='\e[0m'

# ===================== API KEY =====================
ABUSEIPDB_API_KEY="c3107b7e9b3eedf8a54abe0c2bf2a32ba1379afec1467520a757f17259139331136ae37844dad5c4"

# ===================== BLACKLISTS =====================
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

# ===================== FUNCIONES =====================

reverse_ip() {
  awk -F. '{print $4"."$3"."$2"."$1}' <<<"$1"
}

get_geo() {
  curl -s "https://ipinfo.io/${1}/json" \
    | jq -r '.ip, .city, .region, .country, .org' \
    | paste -sd " | "
}

show_whois() {
  echo -e "\n${CYAN}🧾 WHOIS básico (RDAP):${NC}"
  local rdap
  rdap=$(curl -s "https://rdap.arin.net/registry/ip/$1")
  echo -e "  - CIDR:    $(jq -r '.startAddress + "/" + .prefixLength' <<<"$rdap")"
  echo -e "  - NetName: $(jq -r '.name'           <<<"$rdap")"
  echo -e "  - Country: $(jq -r '.country'        <<<"$rdap")"
}

check_dnsbls() {
  local ip=$1 rev_ip=$(reverse_ip "$ip") count=0 total=${#blacklists[@]}
  echo -e "\n📛 ${BOLD}DNSBL Check:${NC}"
  for bl in "${!blacklists[@]}"; do
    if dig +short "${rev_ip}.${bl}" | grep -qE '127\.0\.0\.[0-9]+'; then
      echo "  - Listada en ${YELLOW}$bl${NC}"
      ((count++))
    fi
  done
  DNSBL_TOTAL=$count
  local color=${count:-0}
  if (( count == 0 )); then color=$GREEN; lbl="BAJO"; elif (( count <= 2 )); then color=$YELLOW; lbl="MEDIO"; else color=$RED; lbl="ALTO"; fi
  echo -e "  - ${color}Riesgo DNSBL: $lbl${NC}"
}

check_abuseipdb() {
  local ip=$1 response
  response=$(curl -sG https://api.abuseipdb.com/api/v2/check \
      --data-urlencode "ipAddress=$ip" -d maxAgeInDays=90 \
      -H "Key: $ABUSEIPDB_API_KEY" -H "Accept: application/json")
  echo -e "\n🛡️ ${BOLD}AbuseIPDB Check:${NC}"
  ABUSE_SCORE=$(jq -r '.data.abuseConfidenceScore' <<<"$response")
  ABUSE_REPORTS=$(jq -r '.data.totalReports'           <<<"$response")
  local usage=$(jq -r '.data.usageType'                 <<<"$response")
  local country=$(jq -r '.data.countryCode'             <<<"$response")
  echo -e "  - Puntaje de abuso: ${YELLOW}${ABUSE_SCORE}%${NC}"
  echo -e "  - Reportes:         ${ABUSE_REPORTS}"
  echo -e "  - Uso / País:       ${usage} / ${country}"
  if (( ABUSE_SCORE >= 70 || ABUSE_REPORTS > 10 )); then
    ABUSE_RISK_LEVEL=ALTO; echo -e "  - ${RED}Riesgo AbuseIPDB: ALTO${NC}"
  elif (( ABUSE_SCORE >= 30 || ABUSE_REPORTS > 3 )); then
    ABUSE_RISK_LEVEL=MEDIO; echo -e "  - ${YELLOW}Riesgo AbuseIPDB: MEDIO${NC}"
  else
    ABUSE_RISK_LEVEL=BAJO; echo -e "  - ${GREEN}Riesgo AbuseIPDB: BAJO${NC}"
  fi
}

scan_ports() {
  # devuelve solo la lista: p.ej. "22/tcp,80/tcp,…"
  nmap -Pn --top-ports 20 "$1" \
    | awk '/\/tcp/ {printf "%s,", $1}' \
    | sed 's/,$//'
}

clasifica_riesgo() {
  local r=0
  (( DNSBL_TOTAL   > 0 )) && ((r++))
  (( ABUSE_SCORE   > 25 )) && ((r++))
  [[ -n "$PORTS" && "$PORTS" != "Ninguno" ]] && ((r++))

  case $r in
    0) echo -e "\n${GREEN}🟢 Riesgo: BAJO${NC}"   ;;
    1) echo -e "\n${YELLOW}🟡 Riesgo: MEDIO${NC}" ;;
    *)  echo -e "\n${RED}🔴 Riesgo: ALTO${NC}"     ;;
  esac
}

recomienda() {
  local r=$1
  echo -e "\n${WHITE}💡 Recomendación:${NC}"
  case $r in
    0) echo -e "  - ${GREEN}IP segura actualmente.${NC}" ;;
    1) echo -e "  - ${YELLOW}Monitorear actividad.${NC}" ;;
    *)  echo -e "  - ${RED}Bloquear o investigar a fondo.${NC}" ;;
  esac
}

# ===================== EJECUCIÓN =====================
echo -e "${BOLD}${CYAN}========== ANALIZADOR DE IP ==========${NC}"
read -p "🔎 Ingresa la IP a analizar: " ip
echo -e "\n${WHITE}IP ingresada:${NC} ${YELLOW}${ip}${NC}"
echo "----------------------------------------------"

GEO_DATA=$(get_geo "$ip")
echo -e "\n${WHITE}🌍 Geolocalización:${NC} $GEO_DATA"

show_whois       "$ip"
check_dnsbls     "$ip"
check_abuseipdb  "$ip"

# Capturamos puertos **antes** del resumen
PORTS=$(scan_ports "$ip")

# ====== RESUMEN ORDENADO ======
echo -e "\n${BOLD}${WHITE}==================== RESUMEN ====================${NC}"
echo -e "${WHITE}🌍 Geolocalización:${NC}      $GEO_DATA"
echo -e "${WHITE}📛 DNSBLs detectadas:${NC}    $DNSBL_TOTAL"
echo -e "${WHITE}📊 AbuseIPDB score:${NC}      $ABUSE_SCORE% ($ABUSE_REPORTS rep.)"
echo -e "${WHITE}🔓 Puertos abiertos:${NC}     ${PORTS:-Ninguno}"

clasifica_riesgo
recomienda $(( DNSBL_TOTAL>0 ? DNSBL_TOTAL : ABUSE_SCORE>25 ? 1 : 0 ))

echo -e "\n${BOLD}${CYAN}✅ Análisis finalizado.${NC}"
#Carlos Ramirez
# ------------------------------------------------------------
# === CONTINUACIÓN: Análisis avanzado con la misma IP ($ip) ===
# ------------------------------------------------------------

# RDAP‐WHOIS avanzado
show_whois_advanced() {
  echo -e "\n${CYAN}🧾 WHOIS avanzado (RDAP):${NC}"
  local rdap=$(curl -s "https://rdap.arin.net/registry/ip/$ip")
  echo -e "  - CIDR:    $(jq -r '.startAddress + "/" + .prefixLength' <<<"$rdap")"
  echo -e "  - NetName: $(jq -r '.name' <<<"$rdap")"
  echo -e "  - Country: $(jq -r '.country' <<<"$rdap")"
}

# Escaneo de puertos (solo lista)
scan_ports_advanced() {
  PORTS=$(nmap -Pn --top-ports 20 "$ip" \
    | awk '/\/tcp/ {printf "%s,", $1}' \
    | sed 's/,$//')
  echo -e "\n${CYAN}🔓 Puertos abiertos (top 20):${NC} ${PORTS:-Ninguno}"
}

# Reutiliza DNSBL_TOTAL y ABUSE_SCORE de arriba
clasifica_riesgo_advanced() {
  local r=0
  (( DNSBL_TOTAL   > 0 )) && ((r++))
  (( ABUSE_SCORE   > 25 )) && ((r++))
  [[ -n "$PORTS" && "$PORTS" != "Ninguno" ]] && ((r++))
  case $r in
    0) R="✅ Riesgo BAJO"   ;;
    1) R="⚠️ Riesgo MEDIO" ;;
    *)  R="🚫 Riesgo ALTO"  ;;
  esac
  echo -e "\n📌 ${BOLD}Recomendación avanzada:${NC} $R"
}

echo -e "\n${BOLD}${CYAN}===== Iniciando análisis avanzado =====${NC}"
show_whois_advanced
scan_ports_advanced
clasifica_riesgo_advanced
echo -e "\n${BOLD}${CYAN}✅ Análisis avanzado completado.${NC}"
