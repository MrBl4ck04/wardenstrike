---
name: hunt
description: Run full hunting pipeline on a target
---

Run WardenStrike full hunting pipeline: recon → scan → analyze → validate.

Usage: /hunt <target_domain>

Execute the following:
```bash
cd /home/mrbl4ck/Desktop/mrbl4ck/Hacking/pentestingIA/wardenstrike && wardenstrike hunt $ARGUMENTS
```

After the hunt completes, provide a tactical summary of:
1. Confirmed vulnerabilities and their severity
2. Exploit chains discovered
3. Recommended next steps for manual testing
4. Which findings are most likely to result in bounties
