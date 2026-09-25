# a2kit

Passive AION 2 protocol decoder. No injection. No Npcap/WinPcap required.

## Performance (on real game data, Apple Silicon)

- **Decoding:** 500 MB/s, 60 ns a frame
- **Allocations:** 1 per ~500 frames
- **CPU:** ~6 µs per second of play
- **Latency after a lost packet:** 51 ms median

## Logs

`dump -pcap fight.pcap -log fight.jsonl` writes an `a2log/v0.1` file, which contains a header line, then one JSON line per frame with its raw payload.

```go
var (
	hdr a2log.Header
	dec = json.NewDecoder(file)
)

if err := dec.Decode(&hdr); err != nil {
	return err
}
for dec.More() {
	var line a2log.Frame
	if err := dec.Decode(&line); err != nil {
		return err // a line that is not an a2log frame
	}
	switch e, err := game.Parse(line.Wire(hdr.T0)); {
	case errors.Is(err, game.ErrUnread): // an opcode game does not read yet
	case err != nil: // bytes off the layout, many after a game patch
	default:
		if hit, ok := e.(game.Hit); ok {
			fmt.Println(hit.Actor, hit.Target, hit.Skill, hit.Damage)
		}
	}
}
```

`game/opcode.go` lists every opcode met and which ones are read. `dump -events` prints the same events as JSON lines

Work in progress.