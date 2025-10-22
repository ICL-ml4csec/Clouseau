#!/usr/bin/env bash
###############################################################################
# download.sh  ─ downloader & pre-processor for ATLAS and DARPA's OpTC
#
# REQUIREMENTS
#   • rclone (for Google Drive)        → https://rclone.org/drive/
#   • unzip, curl
#   • Python env with preprocess_atlas.py / preprocess_optc.py on $PATH
#
# QUICK START (background, full pipeline):
#   ./download.sh               # logs to preprocessing.log
#
# FOREGROUND EXAMPLE:
#   ./download.sh --foreground --download atlas --preprocess none
#
# AVAILABLE OPTIONS
#   --download    all|atlas|optc|none        (default: all)
#   --preprocess  all|atlas|optc|none        (default: all)
#   --retain-raw  do not delete raw logs     (default: delete)
#   --foreground                             run in the foreground
#
# The first time you use rclone with Google Drive:
#   sudo apt update && sudo apt install rclone
#   rclone config      # create a remote called  “optc”  with Drive access
#
# Google Drive folder (reference): https://drive.google.com/drive/folders/1n3kkS3KR31KUegn42yk3-e6JkZvf0Caa
###############################################################################
set -euo pipefail

#######################################
# Helper: print timestamped messages
#######################################
log() { printf '%(%F %T)T  %s\n' -1 "$*"; }

#######################################
# Parse CLI
#######################################
DL_CHOICE="all"
PP_CHOICE="all"
DELETE_RAW=true
FOREGROUND=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --download)    DL_CHOICE="${2:-all}";   shift 2;;
    --preprocess)  PP_CHOICE="${2:-all}";   shift 2;;
    --retain-raw)  DELETE_RAW=false;          shift;;
    --foreground)  FOREGROUND=true;         shift;;
    -h|--help)     grep -E '^#( |$)' "$0" | sed 's/^# *//'; exit 0;;
    *)             echo "Unknown arg: $1"; exit 1;;
  esac
done

#######################################
# Re-exec in background unless requested otherwise
#######################################
if ! $FOREGROUND && [[ -z "${__REEXEC_DONE:-}" ]]; then
  log "Launching in background … (tail -f preprocessing.log to watch)"
  nohup env __REEXEC_DONE=1 "$0" "$@" --foreground \
       > preprocessing.log 2>&1 < /dev/null &
  exit 0
fi

log "Started script (PID $$) with options: download=$DL_CHOICE, preprocess=$PP_CHOICE"

#######################################
# DOWNLOAD SECTION
#######################################
download_atlas() {
  if [[ -d atlas ]]; then
    log "atlas/ already exists – skipping download."
    return
  fi
  log "Downloading ATLAS dataset …"
  mkdir -p atlas
  pushd atlas >/dev/null
    curl -L -o atlas-main.zip https://github.com/purseclab/ATLAS/archive/refs/heads/main.zip
    log "Unzipping ATLAS archive …"
    unzip -q -j atlas-main.zip "ATLAS-main/raw_logs/*" -d .
    rm atlas-main.zip
    for z in *.zip; do unzip -q "$z"; done
    rm *.zip
  popd >/dev/null
  log "ATLAS download complete."
}

download_optc() {
  if [[ -d optc ]]; then
    log "optc/ already exists – skipping download."
    return
  fi
  log "Downloading OpTC-NCR dataset via rclone …"
  mkdir -p optc/{OPT1,OPT2,OPT3}/{bro,ecar}
  # OPT1
  rclone copy --drive-shared-with-me optc:OpTCNCR/bro/2019-09-23  optc/OPT1/bro/
  rclone copy --drive-shared-with-me optc:OpTCNCR/ecar/evaluation/23Sep19-red/AIA-201-225 optc/OPT1/ecar/
  # OPT2
  rclone copy --drive-shared-with-me optc:OpTCNCR/bro/2019-09-24  optc/OPT2/bro/
  rclone copy --drive-shared-with-me optc:OpTCNCR/ecar/evaluation/24Sep19/AIA-501-525 optc/OPT2/ecar/
  # OPT3
  rclone copy --drive-shared-with-me optc:OpTCNCR/bro/2019-09-25  optc/OPT3/bro/
  rclone copy --drive-shared-with-me optc:OpTCNCR/ecar/evaluation/25Sept/AIA-51-75   optc/OPT3/ecar/
  log "Extracting any .gz files …"
  find optc -type f -name '*.gz' -exec gunzip {} +
  log "OpTC download complete."
}

case "$DL_CHOICE" in
  all)   download_atlas; download_optc;;
  atlas) download_atlas;;
  optc)  download_optc;;
  none)  log "Skipping all downloads.";;
  *)     echo "Invalid --download choice '$DL_CHOICE'"; exit 1;;
esac

#######################################
# PRE-PROCESSING SECTION
#######################################
preprocess_atlas() {
  if [[ ! -d atlas ]]; then
    log "atlas/ not found – skipping ATLAS preprocessing."
    return
  fi
  log "Running ATLAS preprocessing …"
  python preprocess_atlas.py  --raw-logs-path atlas  --dest-path scenarios
  log "ATLAS preprocessing finished."
}

preprocess_optc() {
  if [[ ! -d optc ]]; then
    log "optc/ not found – skipping OpTC preprocessing."
    return
  fi
  log "Running OpTC preprocessing …"
  python preprocess_optc.py  --raw-logs-path optc  --dest-path scenarios
  log "OpTC preprocessing finished."
}

case "$PP_CHOICE" in
  all)   preprocess_atlas; preprocess_optc;;
  atlas) preprocess_atlas;;
  optc)  preprocess_optc;;
  none)  log "Skipping all preprocessing.";;
  *)     echo "Invalid --preprocess choice '$PP_CHOICE'"; exit 1;;
esac

case "$DELETE_RAW" in
  true)  log "Deleting raw logs …"; rm -rf atlas optc;;
  false) log "Retaining raw logs.";;
  *)     echo "Invalid --retain-raw choice '$DELETE_RAW'"; exit 1;;
esac

log "Pipeline completed successfully ✔"
exit 0
