# Run Registry Key Persistence — Evidence

This document contains validation evidence for the detection rule:

**Persistence via Run Registry Key (T1547.001)**

---

## 🧪 Test Method

Technique validated using:

* Atomic Red Team
* Manual registry modification
* reg.exe persistence simulation

---

## ⚙️ Atomic Test Executed

```
Technique: T1547.001
Test: Add registry run key persistence
```

---

## 📸 Evidence Collected

### Rule Trigger

Detection triggered in Elastic after registry persistence creation.

### Event Details

Registry path, value data, and process responsible for modification were captured.

### Timeline

Event correlation confirmed persistence activity.

---

## ✅ Result

Detection successfully identified persistence behavior via Run Registry Key.

No false positives observed during validation testing.
