#!/bin/sh
# Download the public datasets the corpus is built from (not redistributed here).
set -e
cd "$(dirname "$0")"
mkdir -p data/pages && cd data
HF=https://huggingface.co/api/datasets
for s in train test; do
  curl -sL -o deepset_$s.parquet "$HF/deepset/prompt-injections/parquet/default/$s/0.parquet"
  curl -sL -o gandalf_$s.parquet "$HF/Lakera/gandalf_ignore_instructions/parquet/default/$s/0.parquet"
done
[ -d bipia ] || git clone -q --depth 1 https://github.com/microsoft/BIPIA bipia
# Nostr: the exact events used are listed in ../nostr_event_ids.txt (fetch with nak by id);
# any recent kind-1 sample works for a fresh run:
command -v nak >/dev/null && { nak req -k 1 -l 400 wss://relay.damus.io wss://nos.lol > nostr_posts.jsonl || true; }
cd pages
for u in https://en.wikipedia.org/wiki/Prompt_injection https://genai.owasp.org/llmrisk/llm01-prompt-injection/ \
  https://simonwillison.net/2022/Sep/12/prompt-injection/ https://simonwillison.net/2023/Apr/14/worst-that-can-happen/ \
  https://en.wikipedia.org/wiki/Phishing https://docs.astral.sh/uv/getting-started/installation/ https://brew.sh/ \
  https://en.wikipedia.org/wiki/Bitcoin https://github.com/callebtc/decision-tools https://en.wikipedia.org/wiki/Email_spoofing; do
  n=$(echo "$u" | sed 's#https://##; s#[/.]#_#g'); curl -sL -A "Mozilla/5.0" -o "$n.html" "$u"
done
