# third_party

Dependencies this core patches. Each directory is the module as the Go module
proxy serves it at the version upstream sing-box requires, less the paths
`release/forkop/prune.list` drops, plus the commits on top of it. `go.mod` keeps
upstream's `require` line and replaces the module with the directory;
`release/forkop/third-party.sh` moves a directory to another version, and
`release/forkop/check-tree.sh` checks this table against `go.mod`.

| Directory | Module | Version | Module hash |
| --- | --- | --- | --- |
| wireguard-go | github.com/sagernet/wireguard-go | v0.0.8-0.20260929150556-6731c7387c81 | h1:VsrjoaljEz7jQ1LWbrNyf/scQSQIkVVp7v4nSDrPJ+I= |
| gvisor | github.com/sagernet/gvisor | v0.0.0-20260727.0-sing-box-mod.1 | h1:IdQ7yTKkB2wv8txwshxUroPlO4npOYAV71xb7xQ7Lys= |
| sing-openvpn | github.com/sagernet/sing-openvpn | v0.1.1-0.20260929151220-7c3045dbddce | h1:uB2DkIJLZ9waR/ZLBO9IF/ws5BWg0FEegLi90ibhX5I= |
| sing-vmess | github.com/sagernet/sing-vmess | v0.2.9-0.20260929152519-9b95ab8c9478 | h1:q2eQn4nq8oWGxRm9zXesXSlPr9GEgPrOGzf4iPtzG9A= |
