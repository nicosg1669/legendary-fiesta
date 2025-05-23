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

