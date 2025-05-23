#!/usr/bin/env bash
# ==============================================================================
# check_ip_full.sh — Análisis de IP completo con bloques diferenciados
# Version 1.5 — Añadido Shodan en el reporte final
# ==============================================================================

VERSION="1.5"
ABUSEIPDB_API_KEY="c3107b7e9b3eedf8a54abe0c2bf2a32ba1379afec1467520a757f17259139331136ae37844dad5c4"
SHODAN_API_KEY="o7SxScQXBOXv1BXNnMBGvjkxaynqmqva"

# Colores y estilo
RED='\e[1;91m';   GREEN='\e[1;92m';  YELLOW='\e[1;93m'
CYAN='\e[1;96m';  WHITE='\e[1;97m';   BOLD='\e[1m';  NC='\e[0m'

check_deps() {
  local deps=(curl jq dig nmap whois mail)
  local miss=()
  for cmd in "${deps[@]}"; do
    command -v "$cmd" &>/dev/null || miss+=("$cmd")
  done
  if (("${#miss[@]}")); then
    echo -e "${RED}Faltan dependencias:${NC} ${miss[*]}"
    echo -e "Instálalas con: sudo apt update && sudo apt install -y ${miss[*]}"
    exit 1
  fi
}
check_deps

read -p "🔎 IP a analizar: " IP

# ─── BLOQUE 1: GEO + WHOIS clásico con fallback — Nicolás Saavedra
echo -e "\n${BOLD}${CYAN}===== BLOQUE 1: GEO & WHOIS — Nicolás Saavedra =====${NC}"
echo -e "-> Obteniendo geolocalización desde ipinfo.io..."
GEO=$(curl -s "https://ipinfo.io/${IP}/json" \
      | jq -r '[.ip, .city, .region, .country, .org] | join(" | ")')
echo -e "   🌍 Geolocalización: ${GREEN}${GEO}${NC}"

show_whois() {
  echo -e "-> Realizando consulta WHOIS (puerto 43)…"
  local out
  out=$(whois "$1" 2>/dev/null | grep -Ei 'CIDR|NetName|OrgName|Country' | uniq)
  if [[ -n "$out" ]]; then
    echo -e "   ${out//$'\n'/"\n   "}"
  else
    echo -e "   ⚠️ WHOIS clásico no disponible. Usando RDAP…"
    local rdap
    rdap=$(curl -s "https://rdap.arin.net/registry/ip/$1")
    echo -e "   🧾 CIDR:    $(jq -r '.startAddress + "/" + .prefixLength' <<<"$rdap")"
    echo -e "   🧾 NetName: $(jq -r '.name'                         <<<"$rdap")"
    echo -e "   🧾 Country: $(jq -r '.country'                      <<<"$rdap")"
  fi
}
show_whois "$IP"

# ─── BLOQUE 2: DNSBL & AbuseIPDB — Nicole Picart
echo -e "\n${BOLD}${CYAN}===== BLOQUE 2: DNSBL & AbuseIPDB — Carlos Ramírez =====${NC}"
rev=$(awk -F. '{print $4"."$3"."$2"."$1}' <<<"$IP")
count=0
listed=()
for bl in zen.spamhaus.org pbl.spamhaus.org sbl.spamhaus.org xbl.spamhaus.org \
          bl.spamcop.net dnsbl.sorbs.net b.barracudacentral.org \
          dnsbl-1.uceprotect.net psbl.surriel.com; do
  if dig +short "${rev}.${bl}" | grep -qE '127\.0\.0\.[0-9]+'; then
    echo -e "   - ${RED}En lista:${NC} $bl"
    ((count++)); listed+=("$bl")
  else
    echo -e "   - ${GREEN}No en lista:${NC} $bl"
  fi
done
echo -e "   📛 Total DNSBLs: ${count}"

echo -e "-> Consultando AbuseIPDB…"
resp=$(curl -sG https://api.abuseipdb.com/api/v2/check \
         --data-urlencode "ipAddress=$IP" \
         -d maxAgeInDays=90 \
         -H "Key: $ABUSEIPDB_API_KEY" \
         -H "Accept: application/json")
score=$(jq -r '.data.abuseConfidenceScore // "N/A"' <<<"$resp")
reports=$(jq -r '.data.totalReports // "N/A"'    <<<"$resp")
usage=$(jq -r '.data.usageType // "N/A"'         <<<"$resp")
ctry=$(jq -r '.data.countryCode // "N/A"'       <<<"$resp")
echo -e "   🛡️ AbuseIPDB score: ${YELLOW}${score}%${NC}, reports: ${reports}"
echo -e "      uso: ${usage}, país: ${ctry}"

# ─── BLOQUE 3: SHODAN.IO — Info Adicional─── Carlos Ramírez
echo -e "\n${BOLD}${CYAN}===== BLOQUE 5: SHODAN.IO — Info Adicional =====${NC}"
shodan_json=$(curl -s "https://api.shodan.io/shodan/host/${IP}?key=${SHODAN_API_KEY}")
sh_org=$(jq -r '.org // "N/D"' <<<"$shodan_json")
sh_os=$(jq -r '.os // "N/D"'  <<<"$shodan_json")
sh_ports=$(jq -r '.ports // [] | join(",")' <<<"$shodan_json")
echo -e "   🏢 Organización: ${sh_org}"
echo -e "   💻 SO detectado: ${sh_os}"
echo -e "   🔍 Puertos Shodan: ${sh_ports:-Ninguno}"

# ─── BLOQUE 4: RDAP + Puertos Abiertos — Emilia Silva
echo -e "\n${BOLD}${CYAN}===== BLOQUE 3: RDAP + Puertos Abiertos — Carlos Ramírez =====${NC}"
rdap=$(curl -s "https://rdap.arin.net/registry/ip/$IP")
CIDR=$(jq -r '.startAddress + "/" + .prefixLength' <<<"$rdap")
NETNM=$(jq -r '.name'                         <<<"$rdap")
CTRY2=$(jq -r '.country'                      <<<"$rdap")
echo -e "-> WHOIS RDAP: CIDR=${CIDR}, NetName=${NETNM}, Country=${CTRY2}"

echo -e "-> Escaneo rápido de puertos abiertos (top 20)…"
PORTS=$(nmap -Pn --top-ports 20 "$IP" 2>/dev/null \
          | awk '/\/tcp.*open/ {printf "%s,", $1}' | sed 's/,$//')
[[ -z "$PORTS" ]] && PORTS="Ninguno"
echo -e "   🔓 Puertos abiertos: ${GREEN}${PORTS}${NC}"

echo -e "-> Clasificando riesgo avanzado…"
pts=0
(( count   > 0 )) && ((pts++))
(( score   > 25)) && ((pts++))
[[ "$PORTS" != "Ninguno" ]] && ((pts++))
case $pts in
  0) icon="🟢"; lvl="BAJO";   msg="IP segura."           ;;
  1) icon="🟡"; lvl="MEDIO";  msg="Monitorear actividad." ;;
  *)  icon="🔴"; lvl="ALTO";   msg="Bloquear/investigar." ;;
esac
echo -e "   📌 ${icon} Riesgo Avanzado: ${lvl} — ${msg}"

# ─── BLOQUE 5: Reporte y envío por correo — Jaime M. Ultima Actualizacion :3
echo -e "\n${BOLD}${CYAN}===== BLOQUE 4: REPORTE Y ENVÍO POR CORREO — Jaime M. =====${NC}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORTE="reporte_${IP}_${TIMESTAMP}.txt"

echo -e "📄 Generando reporte en ${REPORTE}…"
{
  echo "===== REPORTE DE ANÁLISIS DE IP ====="
  echo "IP: $IP"
  echo "Fecha: $(date)"

  echo ""
  echo "🌍 GEO: $GEO"
  echo ""
  echo "🧾 WHOIS RDAP: CIDR=$CIDR, NetName=$NETNM, Country=$CTRY2"

  echo ""
  echo -n "📛 DNSBLs ($count): "
  if (( count>0 )); then
    printf "%s " "${listed[@]}"
  else
    echo -n "Ninguna"
  fi

  echo ""
  echo "🛡 AbuseIPDB: $score% — $reports reportes — uso: $usage — país: $ctry"

  echo ""
  echo "🏢 Shodan Org: $sh_org"
  echo "💻 Shodan SO:  $sh_os"
  echo "🔍 Puertos Shodan: ${sh_ports:-Ninguno}"

  echo ""
  echo "🔓 Puertos abiertos (Nmap): $PORTS"

  echo ""
  echo "🚨 Riesgo Avanzado: $lvl — $msg"
} > "$REPORTE"

echo -e "✅ Reporte guardado como ${GREEN}$REPORTE${NC}"

# Forzamos remitente para que coincida con cuenta autenticada
FROM="carlos.ramirez105@inacapmail.cl"
TO="nicolas.montero@inacapmail.cl"

echo -e "📬 Enviando reporte automáticamente a: ${TO}"
echo "Adjunto el reporte de la IP analizada ($IP)." \
  | mail -r "$FROM" -s "Reporte IP $IP" -A "$REPORTE" "$TO"

echo -e "📧 Reporte enviado correctamente a ${GREEN}${TO}${NC}"
echo -e "\n${BOLD}${CYAN}🚀 ANÁLISIS COMPLETO FINALIZADO 🚀${NC}"
