 #!/bin/bash
  # Script completo optimizado

  echo "🔍 PHASE 1: Descubrimiento de subdominios..."
  python3 subdomain_relationship_discovery_v4.py \
    --domains chile.txt \
    --password test.password \
    --ipinfo-token 0bf607ce2c13ac \
    --phase1-only \
    --discovery-workers 2 \
    --amass-timeout 60 \
    --amass-passive \
    --cache-ttl 168 \

  echo "✅ Phase 1 completada. Iniciando Phase 2..."

  echo "🔬 PHASE 2: Análisis completo..."
  python3 subdomain_relationship_discovery_v4.py \
    --domains chile.txt \
    --password test.password \
    --ipinfo-token 0bf607ce2c13ac \
    --phase2-only \
    --processing-workers 4 \
    --batch-size 25 \
    --enable-tls \
    --enable-services \
    --enable-providers \
    --enable-industry \

  echo "🎉 Ejecución completa finalizada!"
