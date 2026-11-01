#!/usr/bin/env bash
# Run a YouTube streaming session THROUGH the UE tunnel (uesimtun0 -> gNB -> GTP-U -> UPF -> Gi).
#
# Usage:  tools/stream_youtube.sh <youtube-url> [duration_seconds]     (default 60 s)
#   RATE=300K   pace the media download (yt-dlp --limit-rate; RATE=0 = unthrottled)
#
# How: a long-lived helper container ("ue-yt", yt-dlp) lives in the UE pod and shares its network
# namespace. Each fetch runs `podman exec ue-yt yt-dlp --source-address <UE tunnel IP> ...`; the
# UE's policy routing ("from <UE IP> lookup rt_uesimtun0") sends it through uesimtun0, across
# the GTP-U link. The video stream is read and discarded (nothing is stored). Fetches repeat
# until the duration elapses. Lab traffic testing only; respect the site's terms of service.
#
# Why exec into one helper instead of `podman run --rm --pod ...` per fetch: on Podman 5.x the
# --rm containers joined to a pod were not removed and piled up as hung yt-dlp processes.
#
# Reported numbers: "video payload" is what yt-dlp wrote; "tunnel RX/TX" is the UE interface
# counter delta and also includes the YouTube page, player JS and manifests, so it is larger.
# Pair with tools/gtpu_monitor.sh to watch the N3 GTP-U link; its total should match tunnel RX
# plus GTP-U/UDP/IP overhead.
set -uo pipefail

URL="${1:?usage: $0 <youtube-url> [duration_seconds]}"
DUR="${2:-60}"
RATE="${RATE:-300K}"
UE_POD="${UE_POD:-ue}"
UE_CTR="${UE_CTR:-ue-ue}"
HELPER="${HELPER:-ue-yt}"
FETCH_TIMEOUT="${FETCH_TIMEOUT:-90}"
IMG="yt-stream:0.1"
HERE="$(cd "$(dirname "$0")" && pwd)"
ERR="$(mktemp -t ytstream)"
trap 'rm -f "$ERR"' EXIT

counter() { podman exec "$UE_CTR" cat "/sys/class/net/uesimtun0/statistics/$1_bytes" 2>/dev/null || echo 0; }

UE_IP="$(podman exec "$UE_CTR" ip -4 -o addr show uesimtun0 2>/dev/null | awk '{print $4}' | cut -d/ -f1)"
[ -n "$UE_IP" ] || { echo "UE tunnel uesimtun0 not found - is the UE attached? (podman logs $UE_CTR)" >&2; exit 1; }

if ! podman image exists "$IMG"; then
  echo "building $IMG (first run only)..." >&2
  podman build -q -t "$IMG" "$HERE/yt-stream" >/dev/null || { echo "image build failed" >&2; exit 1; }
fi

# Helper container in the UE pod (created once, reused across sessions).
if [ "$(podman inspect -f '{{.State.Running}}' "$HELPER" 2>/dev/null)" != "true" ]; then
  podman rm -f "$HELPER" >/dev/null 2>&1 || true
  podman run -d --name "$HELPER" --pod "$UE_POD" "$IMG" sleep infinity >/dev/null || { echo "cannot start helper" >&2; exit 1; }
fi

echo "Streaming session: $URL"
echo "UE tunnel address: $UE_IP   duration: ${DUR}s   pacing: ${RATE}/s   (egress IP: $(podman exec "$UE_CTR" curl -s -m 8 --interface uesimtun0 http://api.ipify.org))"

RX0="$(counter rx)"; TX0="$(counter tx)"
END=$(( $(date +%s) + DUR ))
N=0; TOTAL=0; FAILS=0
while [ "$(date +%s)" -lt "$END" ]; do
  N=$((N + 1))
  START=$(date +%s)
  LIMIT=(); [ "$RATE" != "0" ] && LIMIT=(--limit-rate "$RATE")
  # -f: best single video stream up to 720p (no ffmpeg needed); -o -: write to stdout
  BYTES="$(podman exec "$HELPER" timeout "$FETCH_TIMEOUT" yt-dlp -q --no-warnings --no-part ${LIMIT[@]+"${LIMIT[@]}"} \
      --source-address "$UE_IP" -f 'bv*[height<=720]/b[height<=720]/b' -o - "$URL" 2>"$ERR" | wc -c | tr -d ' ')"
  SECS=$(( $(date +%s) - START )); [ "$SECS" -lt 1 ] && SECS=1
  if [ "${BYTES:-0}" -gt 0 ]; then
    TOTAL=$((TOTAL + BYTES))
    echo "iteration $N: $(awk -v b="$BYTES" 'BEGIN{printf "%.2f MB", b/1e6}') video in ${SECS}s ($(awk -v b="$BYTES" -v s="$SECS" 'BEGIN{printf "%.2f", b*8/1e6/s}') Mbit/s)"
  else
    FAILS=$((FAILS + 1))
    echo "iteration $N: no data in ${SECS}s - $(tail -n 1 "$ERR")"
    [ "$FAILS" -ge 3 ] && { echo "3 failed fetches, giving up" >&2; break; }
    sleep 2
  fi
done

RX1="$(counter rx)"; TX1="$(counter tx)"
echo "session done: $N fetch(es)"
echo "  video payload : $(awk -v b="$TOTAL" 'BEGIN{printf "%.2f MB", b/1e6}')"
echo "  tunnel RX     : $(awk -v b="$((RX1 - RX0))" 'BEGIN{printf "%.2f MB", b/1e6}')   (uesimtun0, includes page/JS/manifests)"
echo "  tunnel TX     : $(awk -v b="$((TX1 - TX0))" 'BEGIN{printf "%.2f MB", b/1e6}')"
echo "  (helper container '$HELPER' left running for reuse; remove with: podman rm -f $HELPER)"
[ "$TOTAL" -gt 0 ]
