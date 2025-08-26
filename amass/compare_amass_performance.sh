#!/bin/bash

if [ $# -ne 1 ]; then
    echo "Uso: $0 <dominio>"
    echo "Ejemplo: $0 example.com"
    exit 1
fi

DOMAIN=$1
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_DIR="amass_performance_${DOMAIN}_${TIMESTAMP}"

mkdir -p "$OUTPUT_DIR"

echo "Iniciando comparación de rendimiento de Amass para el dominio: $DOMAIN"
echo "Directorio de salida: $OUTPUT_DIR"

# Test 1: Solo --active
echo "=== Test 1: Amass con --active ===" | tee "$OUTPUT_DIR/performance_log.txt"
start_time=$(date +%s)
timeout 3000 amass enum -d "$DOMAIN" --active -o "$OUTPUT_DIR/active_only.txt" -log "$OUTPUT_DIR/active_only.log" 2>&1 | tee -a "$OUTPUT_DIR/performance_log.txt"
end_time=$(date +%s)
active_duration=$((end_time - start_time))
active_count=$(wc -l < "$OUTPUT_DIR/active_only.txt" 2>/dev/null || echo "0")

echo "Tiempo con --active: ${active_duration}s" | tee -a "$OUTPUT_DIR/performance_log.txt"
echo "Subdominios encontrados con --active: $active_count" | tee -a "$OUTPUT_DIR/performance_log.txt"

# Test 2: --active y --brute
echo "=== Test 2: Amass con --active y --brute ===" | tee -a "$OUTPUT_DIR/performance_log.txt"
start_time=$(date +%s)
timeout 300 amass enum -d "$DOMAIN" --active --brute -o "$OUTPUT_DIR/active_brute.txt" -log "$OUTPUT_DIR/active_brute.log" 2>&1 | tee -a "$OUTPUT_DIR/performance_log.txt"
end_time=$(date +%s)
brute_duration=$((end_time - start_time))
brute_count=$(wc -l < "$OUTPUT_DIR/active_brute.txt" 2>/dev/null || echo "0")

echo "Tiempo con --active --brute: ${brute_duration}s" | tee -a "$OUTPUT_DIR/performance_log.txt"
echo "Subdominios encontrados con --active --brute: $brute_count" | tee -a "$OUTPUT_DIR/performance_log.txt"

# Resumen
echo "=== RESUMEN DE COMPARACIÓN ===" | tee -a "$OUTPUT_DIR/performance_log.txt"
echo "Dominio analizado: $DOMAIN" | tee -a "$OUTPUT_DIR/performance_log.txt"
echo "Solo --active: ${active_duration}s, $active_count subdominios" | tee -a "$OUTPUT_DIR/performance_log.txt"
echo "--active --brute: ${brute_duration}s, $brute_count subdominios" | tee -a "$OUTPUT_DIR/performance_log.txt"

if [ $brute_duration -gt $active_duration ]; then
    diff_time=$((brute_duration - active_duration))
    echo "El modo --active --brute tardó ${diff_time}s más que solo --active" | tee -a "$OUTPUT_DIR/performance_log.txt"
else
    diff_time=$((active_duration - brute_duration))
    echo "Solo --active tardó ${diff_time}s más que --active --brute" | tee -a "$OUTPUT_DIR/performance_log.txt"
fi

echo "Todos los logs y resultados guardados en: $OUTPUT_DIR"
