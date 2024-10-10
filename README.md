## Convert a Candump dir of log files to json
* Modify the makefile to use your local `candump` dir
* Run as many conversions as you have threads
```bash
  make -j `nproc`
```


## Extract a specific message type from a candump.json
```bash
  cat candump-2024-10-05_094603.json | jq --compact-output '. | select(._meta_.dtype == "uavcan.si.unit.length.Scalar.1.0") | {id: ._meta_.subject_id, meter: .meter}
```
