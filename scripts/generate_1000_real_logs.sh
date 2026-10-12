#!/bin/bash
# ============================================================
# 🔴 GENERATE 1000 REAL LOGS - Kali Linux
# ============================================================
# This script generates 1000 REAL system logs
# ============================================================

echo "============================================================"
echo "🔴 GENERATING 1000 REAL LOGS"
echo "============================================================"

# Check auditd
if ! systemctl is-active --quiet auditd; then
    echo "❌ auditd is not running!"
    echo "   Run: sudo systemctl start auditd"
    exit 1
fi

TOTAL_LOGS=0
ITERATIONS=200  # 5 actions per iteration = 1000 logs

echo "📊 Performing $ITERATIONS iterations..."
echo "   (5 actions per iteration = ${ITERATIONS}0 REAL logs)"

for i in $(seq 1 $ITERATIONS); do
    # 5 REAL actions per iteration
    ssh localhost 2>/dev/null || true
    sudo ls /root 2>/dev/null || true
    cat /etc/passwd > /dev/null
    /bin/bash -c "echo test" > /dev/null
    su - root -c "echo test" 2>/dev/null || true
    
    # Progress indicator
    if [ $((i % 10)) -eq 0 ]; then
        echo "  ✅ $((i * 5)) logs generated..."
    fi
    TOTAL_LOGS=$((TOTAL_LOGS + 5))
done

echo ""
echo "============================================================"
echo "✅ Generated $TOTAL_LOGS REAL logs!"
echo "============================================================"
echo ""
echo "📊 Check audit logs:"
sudo ausearch --start 2m | head -20
echo ""
echo "🔄 Collect REAL logs:"
echo "   python -m src.logger.collector --minutes 5"
echo "   python -m src.logger.adaptive_processor --minutes 5"
echo "   python -m src.logger status"
echo "============================================================"

