#!/bin/bash

# COLORES
RED='\e[1;91m'
GREEN='\e[1;92m'
YELLOW='\e[1;93m'
CYAN='\e[1;96m'
WHITE='\e[1;97m'
BOLD='\e[1m'
NC='\e[0m'

# API KEY
ABUSEIPDB_API_KEY="c3107b7e9b3eedf8a54abe0c2bf2a32ba1379afec1467520a757f17259139331136ae37844dad5c4"

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
  curl -s "https://ipinfo.io/${1}/json" | jq -r '.ip, .city, .region, .country, .org' | paste -sd " | "
}

show_whois() {
  echo -e "\n${CYAN}🧾 WHOIS básico...${NC}"
  whois "$1" | grep -Ei 'CIDR|NetName|OrgName|Country|abuse|contact|descr' | uniq
}

check_dnsbls() {
  local ip="$1"
  local rev_ip=$(reverse_ip "$ip")
  local count=0
  echo -e "\n${CYAN}🔍 Verificando blacklists (DNSBLs)...${NC}"
  for bl in "${!blacklists[@]}"; do
    result=$(dig +short "${rev_ip}.${bl}")
    if [[ -n "$result" ]]; then
      echo -e "${RED}[ENLISTADA]${NC} en ${YELLOW}${bl}${NC} → ${CYAN}${result}${NC}"
      echo -e "  Deslistarse: ${CYAN}${blacklists[$bl]}${NC}"
      ((count++))
    else
      echo -e "${GREEN}[NO]${NC} en ${YELLOW}${bl}${NC}"
    fi
  done
  DNSBL_TOTAL=$count
}

check_abuseipdb() {
  local ip="$1"
  echo -e "\n${CYAN}📡 Consultando AbuseIPDB...${NC}"
  local response=$(curl -sG https://api.abuseipdb.com/api/v2/check \
    --data-urlencode "ipAddress=$ip" \
    -d maxAgeInDays=90 \
    -H "Key: $ABUSEIPDB_API_KEY" \
    -H "Accept: application/json")

  ABUSE_SCORE=$(echo "$response" | jq '.data.abuseConfidenceScore')
  ABUSE_REPORTS=$(echo "$response" | jq '.data.totalReports')
  local country=$(echo "$response" | jq -r '.data.countryCode')
  local usage=$(echo "$response" | jq -r '.data.usageType')

  echo -e "${WHITE}País:${NC} $country"
  echo -e "${WHITE}Tipo de uso:${NC} $usage"
  echo -e "${WHITE}Score de abuso:${NC} ${YELLOW}${ABUSE_SCORE}/100${NC}"
  echo -e "${WHITE}Reportes totales:${NC} $ABUSE_REPORTS"

  if (( ABUSE_SCORE > 25 )); then
    echo -e "${RED}⚠️ IP con reputación dudosa según AbuseIPDB.${NC}"
  else
    echo -e "${GREEN}✅ IP con baja probabilidad de abuso reportado.${NC}"
  fi
}

scan_ports() {
  echo -e "\n${CYAN}🔓 Escaneo rápido de puertos (top 20)...${NC}"
  PORTS=$(nmap -Pn --top-ports 20 "$1" | grep -E '^[0-9]+/tcp' | awk '{print $1}' | paste -sd "," -)
  echo "${PORTS:-Ninguno}"
}

clasifica_riesgo() {
  local riesgo=0
  (( DNSBL_TOTAL > 0 )) && ((riesgo++))
  (( ABUSE_SCORE > 25 )) && ((riesgo++))
  [[ -n "$PORTS" && "$PORTS" != "Ninguno" ]] && ((riesgo++))

  echo ""
  case $riesgo in
    0) echo -e "${GREEN}🟢 Riesgo: BAJO${NC}" ;;
    1) echo -e "${YELLOW}🟡 Riesgo: MODERADO${NC}" ;;
    2|3) echo -e "${RED}🔴 Riesgo: ALTO${NC}" ;;
  esac

  return $riesgo
}

recomienda() {
  local riesgo=$1
  echo -e "\n${WHITE}💡 Recomendación:${NC}"
  case $riesgo in
    0) echo -e "${GREEN}La IP parece segura. Mantenla en observación periódica.${NC}" ;;
    1) echo -e "${YELLOW}Monitorea actividad. Puede volverse maliciosa si su score aumenta.${NC}" ;;
    2|3) echo -e "${RED}Bloquea esta IP en sistemas de perímetro y monitorea tráfico relacionado.${NC}" ;;
  esac
}

# ========= EJECUCIÓN =========

echo -e "${BOLD}${CYAN}========== ANALIZADOR DE IP ==========${NC}"
read -p "🔎 Ingresa la IP a analizar: " ip
echo -e "${WHITE}IP ingresada:${NC} ${YELLOW}${ip}${NC}"
echo "----------------------------------------------"

GEO_DATA=$(get_geo "$ip")
show_whois "$ip"
check_dnsbls "$ip"
check_abuseipdb "$ip"
PORTS=$(scan_ports "$ip")

# ====== RESUMEN ORDENADO ======
echo -e "\n${BOLD}${WHITE}==================== RESUMEN ====================${NC}"
echo -e "${WHITE}🌍 Geolocalización:${NC}      $GEO_DATA"
echo -e "${WHITE}📛 DNSBLs detectadas:${NC}    $DNSBL_TOTAL"
echo -e "${WHITE}📊 AbuseIPDB score:${NC}      $ABUSE_SCORE/100 ($ABUSE_REPORTS reportes)"
echo -e "${WHITE}🔓 Puertos abiertos:${NC}     ${PORTS:-Ninguno}"

clasifica_riesgo
riesgo=$?
recomienda "$riesgo"

echo -e "\n${BOLD}${CYAN}✅ Análisis finalizado.${NC}"
dsfstrddghfdhg