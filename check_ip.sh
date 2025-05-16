#!/usr/bin/env bash
# ==============================================================================
# check_ip_full.sh — Análisis de IP completo con bloques diferenciados
# Version 1.3 — Ajuste: WHOIS clásico con fallback a RDAP
# ==============================================================================

VERSION="1.3"
ABUSEIPDB_API_KEY="c3107b7e9b3eedf8a54abe0c2bf2a32ba1379afec1467520a757f17259139331136ae37844dad5c4"

# ──────────────────────────────────────────────────────────────────────────────
# Colores y estilo
RED='\e[1;91m';   GREEN='\e[1;92m';  YELLOW='\e[1;93m'
CYAN='\e[1;96m';  WHITE='\e[1;97m';   BOLD='\e[1m';  NC='\e[0m'
# ────────────────────────────────────────────────────────────────

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

# ────────────────────────────────────────────────────────────────
# BLOQUE 1 — Nicolás Saavedra: GEO + WHOIS clásico con fallback
echo -e "\n${BOLD}${CYAN}===== BLOQUE 1: GEO & WHOIS — Nicolás Saavedra =====${NC}"

echo -e "-> Obteniendo geolocalización desde ipinfo.io..."
GEO=$(curl -s "https://ipinfo.io/${IP}/json" |
       jq -r '[.ip, .city, .region, .country, .org] | join(" | ")')
echo -e "   🌍 Geolocalización: ${GREEN}${GEO}${NC}"

show_whois() {
  echo -e "-> Realizando consulta WHOIS (puerto 43)…"
  local whois_out
  whois_out=$(whois "$1" 2>/dev/null | grep -Ei 'CIDR|NetName|OrgName|Country' | uniq)
  if [[ -n "$whois_out" ]]; then
    echo -e "   ${whois_out//$'\n'/"\n   "}"
  else
    echo -e "   ⚠️ WHOIS clásico no disponible o puerto 43 bloqueado. Usando RDAP…"
    local rdap
    rdap=$(curl -s "https://rdap.arin.net/registry/ip/$1")
    echo -e "   🧾 CIDR:    $(jq -r '.startAddress + "/" + .prefixLength' <<<"$rdap")"
    echo -e "   🧾 NetName: $(jq -r '.name'                         <<<"$rdap")"
    echo -e "   🧾 Country: $(jq -r '.country'                      <<<"$rdap")"
  fi
}
show_whois "$IP"

# ────────────────────────────────────────────────────────────────
# BLOQUE 2 — Carlos Ramírez: DNSBL & AbuseIPDB clásico
echo -e "\n${BOLD}${CYAN}===== BLOQUE 2: DNSBL & AbuseIPDB — Carlos Ramírez =====${NC}"

echo -e "-> Comprobando listas negras (DNSBLs)…"
rev=$(awk -F. '{print $4"."$3"."$2"."$1}' <<<"$IP")
count=0
for bl in zen.spamhaus.org pbl.spamhaus.org sbl.spamhaus.org xbl.spamhaus.org \
          bl.spamcop.net dnsbl.sorbs.net b.barracudacentral.org \
          dnsbl-1.uceprotect.net psbl.surriel.com; do
  if dig +short "${rev}.${bl}" | grep -qE '127\.0\.0\.[0-9]+'; then
    echo -e "   - ${RED}En lista:${NC} $bl"
    ((count++))
  else
    echo -e "   - ${GREEN}No en lista:${NC} $bl"
  fi
done
echo -e "   📛 ${BOLD}Total DNSBLs:${NC} $count"

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
echo -e "   🛡️ AbuseIPDB score: ${YELLOW}${score}%${NC}, reports: ${YELLOW}${reports}${NC}"
echo -e "      uso: ${usage}, país: ${ctry}"

# ────────────────────────────────────────────────────────────────
# BLOQUE 3 — Carlos Ramírez: Análisis RDAP + Puertos Abiertos
echo -e "\n${BOLD}${CYAN}===== BLOQUE 3: Análisis RDAP + Puertos Abiertos — Carlos Ramírez =====${NC}"

echo -e "-> WHOIS vía RDAP/HTTPS…"
rdap=$(curl -s "https://rdap.arin.net/registry/ip/$IP")
CIDR=$(jq -r '.startAddress + "/" + .prefixLength' <<<"$rdap")
NETNM=$(jq -r '.name'                         <<<"$rdap")
CTRY2=$(jq -r '.country'                      <<<"$rdap")
echo -e "   🧾 CIDR: ${CIDR}, NetName: ${NETNM}, Country: ${CTRY2}"

echo -e "-> Escaneo rápido de puertos abiertos (top 20)…"
open_ports=$(nmap -Pn --top-ports 20 "$IP" 2>/dev/null \
              | awk '/tcp.*open/ {print $1}' | paste -sd ',' -)

if [[ -n $open_ports ]]; then
  # Si hay alguno, los listamos
  echo "$open_ports"
else
  # Si no, indicamos que no hay ninguno :c
  echo "Ninguno"
fi

echo -e "-> Clasificando riesgo avanzado…"
pts=0
(( count        > 0    )) && ((pts++))
(( score        > 25   )) && ((pts++))
[[ -n "$PORTS" && "$PORTS" != "Ninguno" ]] && ((pts++))
case $pts in
  0) icon="🟢"; lvl="BAJO";   msg="IP segura."           ;;
  1) icon="🟡"; lvl="MEDIO";  msg="Monitorear actividad." ;;
  *)  icon="🔴"; lvl="ALTO";   msg="Bloquear/investigar." ;;
esac
echo -e "   📌 ${icon} Riesgo Avanzado: ${lvl} — ${msg}"

# ────────────────────────────────────────────────────────────────
# BLOQUE 4 — Jaime M.: Reporte y envío por correo
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
  echo "🧾 WHOIS RDAP: CIDR=$CIDR, NetName=$NETNM, Country=$CTRY2"
  echo ""
  echo "📛 DNSBLs: $count listas negras"
  echo "🛡 AbuseIPDB: $score% — $reports reportes — uso: $usage — país: $ctry"
  echo ""
  echo "🔓 Puertos abiertos: $PORTS"
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
