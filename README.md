# a2kit

Passive AION 2 protocol decoder. No injection. No Npcap/WinPcap required.

## Performance (on real game data, Apple Silicon)

- **Decoding:** 500 MB/s, 60 ns a frame
- **Allocations:** 1 per ~500 frames
- **CPU:** ~6 µs per second of play
- **Latency after a lost packet:** 51 ms median

## Logs

`dump -pcap fight.pcap -log fight.jsonl` writes an `a2log/v0.1` file, which contains a header line, then one JSON line per frame with its raw payload. Captures hold other players' data, so keep them private.

Work in progress.