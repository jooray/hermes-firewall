#!/bin/sh
# Full dev+test runs of SemIf variants, one after another; logs peak memory use per variant.
cd "$(dirname "$0")"
PY=../decision-tools/Semif/.venv/bin/python
run() {
  tag=$1; shift
  ( while :; do memory_pressure | awk -v t="$tag" '/free percentage/ {print t, $NF}'; sleep 30; done ) >> /tmp/fw-variants-mem.log &
  mon=$!
  env SEMIF_TAG=$tag "$@" $PY score_semif.py test dev
  kill $mon
}
run semif_q8 SEMIF_BITS=8
run semif_q4 SEMIF_BITS=4
run semif_minicpm SEMIF_MODEL=openbmb/MiniCPM5-2B SEMIF_REVISION=12a3808a956f869c767195e9266b59c4d21d92e2
echo ALLDONE
