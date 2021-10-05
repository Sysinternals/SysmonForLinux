# Sysmon For Linux Log View

## Build
SysmonLogView builds as part of Sysmon, is packed into the sysmon binary, and
is installed into /opt/sysmon when Sysmon is installed.

## Usage
SysmonLogView converts Sysmon XML output (usually found in /var/log/syslog)
into a human readable form.  It is a command line filter that expects syslog
data on standard input, and writes its output to standard output.

Pipe data through it as follows:
```
sudo tail -f /var/log/syslog | sudo /opt/sysmon/sysmonLogView
```

## Options
Use -e to specify a comma separated list of event IDs to display, hiding all
others.  Defaults to showing all event IDs.
```
| sudo /opt/sysmon/sysmonLogView -e 1,5
```

Use -r to specify the minimum and maximum record IDs to display - either can
be excluded, so ',15' would show all records from 0 to 15, and '15,' would
show all records from 15 onwards.
```
| sudo /opt/sysmon/sysmonLogView -r 25,30
```

Use -t to specify the start and/or end times. Time format is
YYYY-MM-DD HH:MM[:SS[.nnn]] where nnn is milliseconds.
```
| sudo /opt/sysmon/sysmonLogView -t "2021-01-01 09:00,2021-01-02 09:00"
```

Use -f to specify field values that displayed records must have.
```
| sudo /opt/sysmon/sysmonLogView -f Image=/bin/touch
```

Use -E to specify which fields to display.
```
| sudo /opt/sysmon/sysmonLogView -E Image,SourceIp
```

Use -X to insert an extra carriage return between events.

Use -h or -? to display the help text.

## License
SysmonLogView is licensed under MIT.

