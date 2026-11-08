#!/usr/bin/env python3
"""Generate data/grok_patterns.json from the StreamSets/logstash canonical definitions.

Run once: python3 tools/gen_patterns.py
The JSON file is the artifact loaded by the app; this script is the source of truth.
"""
import json
import pathlib

P = [
    # ---- general ----
    ("general", "USERNAME", r"[a-zA-Z0-9._-]+"),
    ("general", "USER", r"%{USERNAME}"),
    ("general", "BASE10NUM", r"(?<![0-9.+-])(?>[+-]?(?:(?:[0-9]+(?:\.[0-9]+)?)|(?:\.[0-9]+)))"),
    ("general", "BASE16FLOAT", r"\b(?<![0-9A-Fa-f.])(?:[+-]?(?:0x)?(?:(?:[0-9A-Fa-f]+(?:\.[0-9A-Fa-f]*)?)|(?:\.[0-9A-Fa-f]+)))\b"),
    ("general", "NUMBER", r"%{BASE10NUM}"),
    ("general", "BASE16NUM", r"(?<![0-9A-Fa-f])(?:[+-]?(?:0x)?(?:[0-9A-Fa-f]+))"),
    ("general", "INT", r"(?:[+-]?(?:[0-9]+))"),
    ("general", "NONNEGINT", r"\b(?:[0-9]+)\b"),
    ("general", "POSINT", r"\b(?:[1-9][0-9]*)\b"),
    ("general", "WORD", r"\b\w+\b"),
    ("general", "NOTSPACE", r"\S+"),
    ("general", "SPACE", r"\s*"),
    ("general", "DATA", r".*?"),
    ("general", "GREEDYDATA", r".*"),
    ("general", "QUOTEDSTRING", r'''(?>(?<!\\)(?>"(?>\\.|[^\\"])+"|""|(?>'(?>\\.|[^\\'])+')|''|(?>`(?>\\.|[^\\`])+`)|``))'''),
    ("general", "UUID", r"[A-Fa-f0-9]{8}-(?:[A-Fa-f0-9]{4}-){3}[A-Fa-f0-9]{12}"),
    # ---- datetime ----
    ("datetime", "MONTH", r"\b(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\b"),
    ("datetime", "MONTHNUM", r"(?:0?[1-9]|1[0-2])"),
    ("datetime", "MONTHNUM2", r"(?:0[1-9]|1[0-2])"),
    ("datetime", "MONTHDAY", r"(?:(?:0[1-9])|(?:[12][0-9])|(?:3[01])|[1-9])"),
    ("datetime", "DAY", r"(?:Mon(?:day)?|Tue(?:sday)?|Wed(?:nesday)?|Thu(?:rsday)?|Fri(?:day)?|Sat(?:urday)?|Sun(?:day)?)"),
    ("datetime", "YEAR", r"(?>\d\d){1,2}"),
    ("datetime", "HOUR", r"(?:2[0123]|[01]?\d)"),
    ("datetime", "MINUTE", r"(?:[0-5]\d)"),
    ("datetime", "SECOND", r"(?:(?:[0-5]?\d|60)(?:[:.,]\d+)?)"),
    ("datetime", "TIME", r"(?!<[0-9])%{HOUR}:%{MINUTE}(?::%{SECOND})(?![0-9])"),
    ("datetime", "DATE_US", r"%{MONTHNUM}[/-]%{MONTHDAY}[/-]%{YEAR}"),
    ("datetime", "DATE_EU", r"%{MONTHDAY}[./-]%{MONTHNUM}[./-]%{YEAR}"),
    ("datetime", "ISO8601_TIMEZONE", r"(?:Z|[+-]%{HOUR}(?::?%{MINUTE}))"),
    ("datetime", "ISO8601_SECOND", r"(?:%{SECOND}|60)"),
    ("datetime", "TIMESTAMP_ISO8601", r"%{YEAR}-%{MONTHNUM}-%{MONTHDAY}[T ]%{HOUR}:?%{MINUTE}(?::%{SECOND})?%{ISO8601_TIMEZONE}?"),
    ("datetime", "DATE", r"%{DATE_US}|%{DATE_EU}"),
    ("datetime", "DATESTAMP", r"%{DATE}[- ]%{TIME}"),
    ("datetime", "TZ", r"(?:[PMCE][SD]T|UTC)"),
    ("datetime", "DATESTAMP_RFC822", r"%{DAY} %{MONTH} %{MONTHDAY} %{YEAR} %{TIME} %{TZ}"),
    ("datetime", "DATESTAMP_RFC2822", r"%{DAY}, %{MONTHDAY} %{MONTH} %{YEAR} %{TIME} %{ISO8601_TIMEZONE}"),
    ("datetime", "DATESTAMP_OTHER", r"%{DAY} %{MONTH} %{MONTHDAY} %{TIME} %{TZ} %{YEAR}"),
    ("datetime", "DATESTAMP_EVENTLOG", r"%{YEAR}%{MONTHNUM2}%{MONTHDAY}%{HOUR}%{MINUTE}%{SECOND}"),
    # ---- log ----
    ("log", "PROG", r"[\w._/%-]+"),
    ("log", "SYSLOGTIMESTAMP", r"%{MONTH} +%{MONTHDAY} %{TIME}"),
    ("log", "SYSLOGPROG", r"%{PROG:program}(?:\[%{POSINT:pid}\])?"),
    ("log", "SYSLOGHOST", r"%{IPORHOST}"),
    ("log", "SYSLOGFACILITY", r"<%{NONNEGINT:facility}.%{NONNEGINT:priority}>"),
    ("log", "SYSLOGBASE", r"%{SYSLOGTIMESTAMP:timestamp} (?:%{SYSLOGFACILITY} )?%{SYSLOGHOST:logsource} %{SYSLOGPROG}:"),
    ("log", "HTTPDATE", r"%{MONTHDAY}/%{MONTH}/%{YEAR}:%{TIME} %{INT}"),
    ("log", "QS", r"%{QUOTEDSTRING}"),
    ("log", "COMMONAPACHELOG", r'''%{IPORHOST:clientip} %{USER:ident} %{USER:auth} \[%{HTTPDATE:timestamp}\] "(?:%{WORD:verb} %{NOTSPACE:request}(?: HTTP/%{NUMBER:httpversion})?|%{DATA:rawrequest})" %{NUMBER:response} (?:%{NUMBER:bytes}|-)'''),
    ("log", "COMBINEDAPACHELOG", r"%{COMMONAPACHELOG} %{QS:referrer} %{QS:agent}"),
    ("log", "LOGLEVEL", r"([Aa]lert|ALERT|[Tt]race|TRACE|[Dd]ebug|DEBUG|[Nn]otice|NOTICE|[Ii]nfo|INFO|[Ww]arn?(?:ing)?|WARN?(?:ING)?|[Ee]rr?(?:or)?|ERR?(?:OR)?|[Cc]rit?(?:ical)?|CRIT?(?:ICAL)?|[Ff]atal|FATAL|[Ss]evere|SEVERE|EMERG(?:ENCY)?|[Ee]merg(?:ency)?)"),
    # ---- network ----
    ("network", "MAC", r"(?:%{CISCOMAC}|%{WINDOWSMAC}|%{COMMONMAC})"),
    ("network", "CISCOMAC", r"(?:(?:[A-Fa-f0-9]{4}\.){2}[A-Fa-f0-9]{4})"),
    ("network", "COMMONMAC", r"(?:(?:[A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2})"),
    ("network", "WINDOWSMAC", r"(?:(?:[A-Fa-f0-9]{2}-){5}[A-Fa-f0-9]{2})"),
    ("network", "HOSTNAME", r"\b(?:[0-9A-Za-z][0-9A-Za-z-]{0,62})(?:\.(?:[0-9A-Za-z][0-9A-Za-z-]{0,62}))*(\.?|\b)"),
    ("network", "HOSTPORT", r"%{IPORHOST}:%{POSINT}"),
    ("network", "IPORHOST", r"(?:%{HOSTNAME}|%{IP})"),
    ("network", "IP", r"(?:%{IPV6}|%{IPV4})"),
    ("network", "IPV6", r"((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?"),
    ("network", "IPV4", r"(?<![0-9])(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))(?![0-9])"),
    # ---- path ----
    ("path", "PATH", r"(?:%{UNIXPATH}|%{WINPATH})"),
    ("path", "UNIXPATH", r"(?>/(?:[\w_%!$@:.,~-]+|\\.)*)+"),
    ("path", "TTY", r"(?:/dev/(pts|tty[pq]?)(\w+)?/?(?:[0-9]+))"),
    ("path", "WINPATH", r"(?>[A-Za-z]+:|\\)(?:\\[^\\?*]*)+"),
    ("path", "URIPROTO", r"[A-Za-z]+(\+[A-Za-z+]+)?"),
    ("path", "URIHOST", r"%{IPORHOST}(?::%{POSINT:port})?"),
    ("path", "URIPATH", r"(?:/[A-Za-z0-9$.+!*'(){},~:;=@#%_\-]*)+"),
    ("path", "URIPARAM", r"\?[A-Za-z0-9$.+!*'|(){},~@#%&/=:;_?\-\[\]]*"),
    ("path", "URIPATHPARAM", r"%{URIPATH}(?:%{URIPARAM})?"),
    ("path", "URI", r"%{URIPROTO}://(?:%{USER}(?::[^@]*)?@)?(?:%{URIHOST})?(?:%{URIPATHPARAM})?"),
]


def main() -> None:
    out = pathlib.Path(__file__).resolve().parent.parent / "data" / "grok_patterns.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    payload = [{"category": c, "name": n, "pattern": p} for c, n, p in P]
    out.write_text(json.dumps(payload, indent=1) + "\n", encoding="utf-8")
    print(f"wrote {out} ({len(payload)} patterns)")


if __name__ == "__main__":
    main()
