SpitEvents
==========
Useful scripts to parse various events/logs including Windows Events

So far, there is:
spitwinevents.pl - Useful for extracting windows events in evtx to CSV

Usage
=====
Extract me relevant authentication events from security-events.evtx:
spitwinevents.pl -p auth security-events.evtx

Extract me events with ID 4624,4634 (login/logoff):
spitwinevents.pl -e 4624,4634 security-events.evtx

Extract me login/logoff authentication events with additional fields specified in -f:
spitwinevents.pl -f TargetUserName,TargetDomainName,LogonType,TargetLogonId,IpAddress,IpPort -e 4624,4634 security-events.evtx


Requirements
============
In short, it requires Perl, Parse::Evtx and XML::Simple.

But I guess copy & paste from the perl file will help you:
use Parse::Evtx;
use Parse::Evtx::Chunk;
use Carp::Assert;
use XML::Simple;
use IO::File 1.14;

