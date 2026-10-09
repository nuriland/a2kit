# a2kit

A passive AION 2 protocol toolkit, library and CLI (capture, decode, telemetry, analysis) with a structured a2log session format. No injection. No Npcap/WinPcap required.

## CLI
Download `a2k` for your system from the [releases](https://github.com/nuriland/a2kit/releases), or install it as a CLI tool:

```
go install github.com/nuriland/a2kit/cmd/a2k@latest
```

On Linux, a2k needs `libpcap` to capture live, and `libpcap-dev` to build. A build without cgo reads recordings, but cannot capture.

### Use

```bash
a2k help                                      # list all available commands
a2k watch                                     # what happens in the game, live
a2k record -log fight.jsonl                   # save the game's session
a2k show fight.pcap                           # read the saved game session
a2k export fight.pcap -o fight.jsonl          # a log to share
a2k timeline fight.pcap -o fight.trace.json   # a timeline reconstruction via ui.perfetto.dev
a2k stats fight.pcap                          # which message types came, and which a2k decodes
a2k conns down.pcap                           # every TCP connection in a recording, and which were the game's
```

Example usage of `a2k show`:
```
   21.050  Hit        actor=37365 target=15943 skill=11020000 damage=36 type=2 scalar=10000
```

From the server list on, before a world server is picked:
```
    1.006  Servers    list=[1301:LIVE_Light_001 3245/7500 restricted 1302:LIVE_Light_002 2374/7000 ...]
    5.015  Redirect   server=1304 host=10.0.0.2 port=13328
```

## Live capture

`watch` and `record` find the game's connection by themselves. Needs priviledged access to run on all platforms (Win, Linux, MacOS).

### Windows
  - Doesn't require Npcap or WinPcap installed, it runs on native pktmon monitor.
  - It captures on every adapter at once (`nics`), a VPN's tunnel included, by default. `a2k adapters` lists the adapters.

## Recording and sharing

`a2k record` saves a session two ways, and can do both at once:
- `-log fight.jsonl`, a log of the game's messages only, with their raw bytes
- `fight.pcap`, a recording of all the adapter's TCP traffic. DO NOT SHARE THESE PUBLICLY.

The log, `a2k export` and `a2k timeline` leave out the messages that name your account (`Login`, `Account`, `Characters`). `-account` keeps them. What `show` and `watch` print still includes them.

## a2log

`a2k record -log` and `a2k export` write an a2log file format.

```json
{"schema":"a2log/v0.1","decoder":"github.com/nuriland/a2kit@v0.3.0","source":{"kind":"pcap","path":"fight.pcap"},"t0":"2026-09-23T18:00:00.123Z"}
{"t":0,"opcode":"04 38","flags":["server"],"src":"10.0.0.2:13328","dst":"10.0.0.1:10000","payload":"x3wEAPWjAuAmqAAAAkvtn0EBAAAAkE4kAQA="}
{"t":51,"opcode":"42 36","flags":["server"],"src":"10.0.0.2:13328","dst":"10.0.0.1:10000","payload":"x3wAAw=="}
```

The header:

| key | |
|---|---|
| `schema` | `a2log/v0.1`
| `decoder` | the a2kit module and version that wrote the log |
| `source` | `kind` is `pcap`, `live` or `feed` --  `path` is the file, or the adapter |
| `t0` | the first message's time, UTC

Each message:

| key | |
|---|---|
| `t` | milliseconds after `t0`, negative for a message completed out of order |
| `opcode` | the message type, two bytes in wire order |
| `flags` | `server` or `client`, then `lz4`, `bundled`, `resynced` |
| `src`, `dst` | the endpoints |
| `payload` | the bytes after the type, base64 |

```bash
a2k show fight.jsonl                                                                   # what the log says
jq -r 'select(.opcode) | .opcode' fight.jsonl | sort | uniq -c | sort -rn              # messages by type
jq -c 'select(.opcode == "04 38")' fight.jsonl                                         # the hits
jq -r 'select(.opcode == "04 38") | .payload' fight.jsonl | head -1 | base64 -d | xxd  # one hit's bytes
```

`a2k show` on the three lines above:

```
    0.000  Hit        actor=37365 target=15943 skill=11020000 damage=36 type=2 scalar=10000
    0.051  Death      entity=15943 flag=3
```

`a2kit.Open` reads a log the same way it reads a recording. `a2log.NewReader` reads one on its own, and gives the frames `game.Parse` takes:

```go
r, err := a2log.NewReader(file)
if err != nil {
	return err
}
for f, err := range r.Frames() {
	if err != nil {
		return err
	}
	e, _ := game.Parse(f) // nil when game does not read it
	if hit, ok := e.(game.Hit); ok {
		fmt.Println(hit.Actor, hit.Target, hit.Damage)
	}
}
```

Warning: A log holds what the game sent, players' names among it. Your account ID and character list are left out unless it was written with `-account`.

## As a library

```
go get github.com/nuriland/a2kit
```

```go
r, err := a2kit.Open("fight.pcap", a2kit.Config{})
if err != nil {
	return err
}
defer r.Close()

for m, err := range r.Messages() {
	if err != nil {
		return err
	}
	if hit, ok := m.Event.(game.Hit); ok {
		fmt.Println(hit.Actor, hit.Target, hit.Skill, hit.Damage)
	}
}
fmt.Printf("%+v\n", r.Summary()) // how many were decoded, the game's connection, what was lost
```

Work in progress.