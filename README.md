# a2kit

Passive AION 2 protocol decoder. No injection.

## Performance (on real game data, Apple Silicon)

- **Decoding:** 500 MB/s, 60 ns a frame
- **Allocations:** 1 per ~500 frames
- **CPU:** ~6 µs per second of play
- **Latency after a lost packet:** 51 ms median

Work in progress.