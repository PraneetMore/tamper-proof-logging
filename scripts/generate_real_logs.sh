#!/bin/bash
# ============================================================
# 🔴 REAL LOG GENERATOR - Kali Linux
# ============================================================
# This script performs ACTUAL system actions that generate
# REAL auditd logs. These are NOT test data.
# ============================================================

echo "============================================================"
echo "🔴 REAL LOG GENERATOR - Kali Linux"
echo "============================================================"
echo "📊 This script performs actual system actions"
echo "🟢 Generated logs are REAL (collected by auditd)"
echo "============================================================"

# Check if auditd is running
if ! systemctl is-active --quiet auditd; then
    echo "❌ auditd is not running!"
    echo "   Run: sudo systemctl start auditd"
    exit 1
fi

# Create log file
LOG_FILE="real_logs_generated.txt"
echo "🔴 REAL LOG GENERATION LOG" > $LOG_FILE
echo "Date: $(date)" >> $LOG_FILE
echo "============================================================" >> $LOG_FILE

TOTAL_ACTIONS=0
ITERATIONS=${1:-10}  # Default 10 iterations

echo "📊 Performing $ITERATIONS iterations of real system actions..."

for i in $(seq 1 $ITERATIONS); do
    echo "Iteration $i..." >> $LOG_FILE
    
    # Action 1: REAL SSH attempt (generates LOGIN logs)
    echo "  SSH attempt..." >> $LOG_FILE
    ssh localhost 2>/dev/null || true
    ((TOTAL_ACTIONS++))
    
    # Action 2: REAL sudo command (generates USER_CMD logs)
    echo "  Sudo command..." >> $LOG_FILE
    sudo ls /root 2>/dev/null || true
    ((TOTAL_ACTIONS++))
    
    # Action 3: REAL file access (generates OPENAT logs)
    echo "  File access..." >> $LOG_FILE
    cat /etc/passwd > /dev/null
    cat /etc/shadow 2>/dev/null || true
    ((TOTAL_ACTIONS++))
    
    # Action 4: REAL process creation (generates EXECVE logs)
    echo "  Process creation..." >> $LOG_FILE
    /bin/bash -c "echo test_iteration_$i" > /dev/null
    python3 -c "print('test_iteration_$i')" > /dev/null
    ((TOTAL_ACTIONS++))
    
    # Action 5: REAL user switch (generates USER_START logs)
    echo "  User switch..." >> $LOG_FILE
    su - root -c "echo test" 2>/dev/null || true
    ((TOTAL_ACTIONS++))
    
    echo "  ✅ Completed iteration $i ($((i * 5)) actions)" >> $LOG_FILE
    echo -n "."
done

echo ""
echo "============================================================"
echo "✅ REAL Log Generation Complete!"
echo "============================================================"
echo "📊 Total Actions Performed: $TOTAL_ACTIONS"
echo "📁 Log file: $LOG_FILE"
echo ""
echo "🔄 Now collect REAL logs with:"
echo "   python -m src.logger.collector --minutes 5"
echo ""
echo "🔄 Process REAL logs with:"
echo "   python -m src.logger.adaptive_processor --minutes 5"
echo "============================================================"

# Show what was generated
echo ""
echo "📊 Audit log count:"
sudo ausearch --start 2m | grep -c "type=" 2>/dev/null || echo "0 (no audit logs found)"

