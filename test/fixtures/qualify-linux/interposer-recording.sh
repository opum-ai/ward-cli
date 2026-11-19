#!/bin/sh
umask 077
unset PWD OLDPWD SHLVL _
for a in "$@"; do case $a in *'
'*) exit 97;; esac; done
case $TPM2TOOLS_TCTI in *'
'*) exit 97;; esac
entries=$(/usr/bin/env -u _ -u SHLVL -u PWD -u OLDPWD /usr/bin/env -0 | tr -cd '\000' | wc -c)
lines=$(/usr/bin/env -u _ -u SHLVL -u PWD -u OLDPWD /usr/bin/env | wc -l)
{
  printf 'CALL %s\n' 'tpm2_sessionconfig'
  printf 'TCTI %s\n' "$TPM2TOOLS_TCTI"
  if [ "$((entries))" -eq "$((lines))" ] && [ "$((entries))" -gt 0 ]; then
  /usr/bin/env -u _ -u SHLVL -u PWD -u OLDPWD /usr/bin/env | while IFS= read -r line; do
    case $line in *=*) name=${line%%=*}; value=${line#*=};; *) name=$line; value=;; esac
    digest=$(printf '%s' "$value" | { sha256sum 2>/dev/null || shasum -a 256; } | cut -d' ' -f1)
    printf 'ENV %s %s\n' "$name" "$digest"
  done
  else printf 'ENV-SPLIT\n'; fi
  for a in "$@"; do printf 'ARG %s\n' "$a"; done
  printf 'END\n'
} >> '/run/ward/tools.log' || exit 98
capture='/run/ward/tools.log.out.'$$
/usr/bin/env -u _ -u SHLVL -u PWD -u OLDPWD '/usr/bin/tpm2_sessionconfig' "$@" > "$capture"; rc=$?
cat "$capture"
{ printf 'OUT-BEGIN\n'; cat "$capture"; printf '\nOUT-END\nRC %s\nDONE\n' "$rc"; } >> '/run/ward/tools.log' || { rm -f "$capture"; exit 98; }
rm -f "$capture"
exit "$rc"
