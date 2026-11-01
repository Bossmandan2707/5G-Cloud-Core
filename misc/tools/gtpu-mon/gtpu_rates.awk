# Reads `tcpdump -nn -l -tt -q udp port 2152` lines, e.g.
#   1760352000.123456 IP 127.0.0.1.2152 > 127.0.0.7.2152: UDP, length 1448
# and prints one line per second. Busybox-awk compatible (no strftime/gensub).
#
# Direction on the N3 link inside the core pod:
#   UL  gNB 127.0.0.1  -> UPF 127.0.0.7   (user traffic leaving the UE)
#   DL  UPF 127.0.0.7  -> gNB 127.0.0.1   (user traffic toward the UE)
#   OTH anything else on UDP 2152 (e.g. SMF 127.0.0.4 <-> UPF GTP-U echo/path management)
# "bytes" are UDP payload bytes = GTP-U header + the tunnelled user packet.

function hms(s,   x, h, m) {
    x = s % 86400; h = int(x / 3600); m = int((x % 3600) / 60)
    return sprintf("%02d:%02d:%02d", h, m, x % 60)
}
function flush(sec,   ulk, dlk, bar, n, i) {
    ulk = ulb[sec] * 8 / 1000; dlk = dlb[sec] * 8 / 1000
    n = int(dlk / 1000); if (n > 40) n = 40
    bar = ""; for (i = 0; i < n; i++) bar = bar "#"
    printf "%s  %7d %10.1f   %7d %10.1f   %6d  %s\n", hms(sec), ulp[sec], ulk, dlp[sec], dlk, othp[sec], bar
    fflush()
    tulp += ulp[sec]; tulb += ulb[sec]; tdlp += dlp[sec]; tdlb += dlb[sec]; toth += othp[sec]
    if (dlk > peakdl) peakdl = dlk
    if (ulk > peakul) peakul = ulk
    if (dlp[sec] + ulp[sec] > 0) active++
    secs++
    delete ulp[sec]; delete ulb[sec]; delete dlp[sec]; delete dlb[sec]; delete othp[sec]
}
BEGIN {
    print "GTP-U (UDP 2152) on the N3 link, inside the core pod - one row per second"
    print "UL = gNB 127.0.0.1 -> UPF 127.0.0.7    DL = UPF 127.0.0.7 -> gNB 127.0.0.1    '#' = 1 Mbit/s of DL"
    print ""
    printf "%-8s  %7s %10s   %7s %10s   %6s  %s\n", "UTC", "UL pkt", "UL kbit/s", "DL pkt", "DL kbit/s", "other", "DL load"
    print "--------  ------------------   ------------------   ------  ----------------------------------------"
}
$2 == "IP" {
    sec = int($1)
    if (cur == 0) cur = sec
    if (sec > cur) {
        for (s = cur; s < sec; s++) flush(s)   # also emits zero rows for silent seconds
        cur = sec
    }
    src = $3; dst = $5; sub(/:$/, "", dst)
    len = $NF + 0
    if (src ~ /^127\.0\.0\.1\./ && dst ~ /^127\.0\.0\.7\./)      { ulp[sec]++; ulb[sec] += len }
    else if (src ~ /^127\.0\.0\.7\./ && dst ~ /^127\.0\.0\.1\./) { dlp[sec]++; dlb[sec] += len }
    else                                                         { othp[sec]++ }
}
END {
    if (cur != 0) flush(cur)
    print ""
    print "=== SUMMARY ==="
    printf "duration         : %d s (%d active)\n", secs, active
    printf "uplink   (UE->net): %d packets, %.2f MB, peak %.2f Mbit/s\n", tulp, tulb / 1e6, peakul / 1000
    printf "downlink (net->UE): %d packets, %.2f MB, peak %.2f Mbit/s\n", tdlp, tdlb / 1e6, peakdl / 1000
    if (active > 0) printf "avg downlink     : %.2f Mbit/s over active seconds\n", (tdlb * 8 / 1e6) / active
    if (tdlp > 0)   printf "avg DL GTP-U pkt : %.0f bytes\n", tdlb / tdlp
    printf "other GTP-U      : %d packets (SMF<->UPF echo / path management)\n", toth
}
