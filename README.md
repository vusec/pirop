# PIROP

Position-Independent Return-Oriented Programming (PIROP) is a technique
for applying a ROP attack without leveraging an information disclosure
primitive to disclose the location of gadgets. As such it is capable of
bypassing code randomization techniques and defenses against information leakage.
Please find more about PIROP in the [paper](https://download.vusec.net/papers/pirop_eurosp18.pdf)
and for the demo's check out https://www.vusec.net/projects/pirop/.

## Asterisk exploits

The Asterisk exploits that launch a shell and inject a shellcode leverage
the CVE-2012-5976 vulnerability. The deb packages of Asterisk with the
vulnerability can be found in [./CVE-2012-5976-asterisk.tar.gz](./CVE-2012-5976-asterisk.tar.gz).
Some information about the setup can be found in [./setup\_info.txt](./setup_info.txt).

The exploit launching a shell can be found at [./asterisk/attacks/execve/asterisk\_execve\_no\_rec.py](./asterisk/attacks/execve/asterisk_execve_no_rec.py).

The exploit injecting a shellcode can be found at [./asterisk/attacks/mprotect/asterisk\_mprotect\_no\_rec.py](./asterisk/attacks/mprotect/asterisk_mprotect_no_rec.py).

