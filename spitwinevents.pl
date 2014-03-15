#!/usr/bin/env perl
# Windows event file parse. (C) 2014. Vlatko Kosturjak. Distributed under GPL.
# Custom evtx parsing based on Parse-Evtx samples.

use strict;

use Parse::Evtx;
use Parse::Evtx::Chunk;
use Carp::Assert;
use XML::Simple;
use IO::File 1.14;
use Getopt::Long;

my $configfile="$ENV{HOME}/.spitwinevents";
my %config;
my $sep=";";
my @filtevents;
my @filtfields;

if (-e $configfile) {
	open(CONFIG,"<$configfile") or next;
	while (<CONFIG>) {
	    chomp;                  # no newline
	    s/#.*//;                # no comments
	    s/^\s+//;               # no leading white
	    s/\s+$//;               # no trailing white
	    next unless length;     # anything left?
	    my ($var, $value) = split(/\s*=\s*/, $_, 2);
	    $config{$var} = $value;
	} 
	close(CONFIG);
}

Getopt::Long::Configure ("bundling");

my $result = GetOptions (
	"p|profile=s" => \$config{'profile'},
	"s|separator=s" => \$config{'separator'},
	"e|events=s@" => \$config{'events'},
	"f|fields=s@" => \$config{'fields'},
	"v|verbose+"  => \$config{'verbose'},
	"h|help" => \&help
);

sub help () {
	print "Sorry, no help yet. See README or source.\n"
}

# set parameters
if ($config{'events'}) {
	@filtevents = split(/,/,join(',',@{$config{'events'}}));
} 
if ($config{'fields'}) {
	@filtfields = split(/,/,join(',',@{$config{'fields'}}));
}
if ($config{'profile'}) {
	if ($config{'profile'} eq "auth") {
		push @filtevents, (4624,4634);
		push @filtfields, ('TargetUserName','TargetDomainName','LogonType','TargetLogonId','IpAddress','IpPort');
	}
} 
if ($config{'separator'}) {
	$sep = $config{'separator'};
}

# main()

my $fh = IO::File->new(shift, "r");
if (!defined $fh) {
	print "Unable to open file: $!\n";
	exit 1;	
}

assert(defined $fh);
my $file;
$file = Parse::Evtx->new('FH' => $fh);
if (!defined $file) {
    # if it's not a complete file, is it a chunk then?
    $file = Parse::Evtx::Chunk->new('FH' => $fh );
};
assert(defined $file);
binmode(STDOUT, ":utf8");
select((select(STDOUT), $|=1)[0]);


print '"Time"'.$sep.'"EventID"'.$sep.'"Computer"'.$sep;
foreach my $field (@filtfields) {
	print "\"$field\"$sep";
}
print "\n";

my $event = $file->get_first_event();
while (defined $event) {
	my $xml=$event->get_xml();
	my $xmls=XMLin($xml, ForceArray => 1, KeyAttr => '', SuppressEmpty => '' );
	my $fcomputer=$xmls->{'System'}->[0]->{'Computer'}->[0];
	my $feventid=$xmls->{'System'}->[0]->{'EventID'}->[0];
	my $ftimestamp=$xmls->{'System'}->[0]->{'TimeCreated'}->[0]->{'SystemTime'};
	if ((!@filtevents) or (grep {$_ eq $feventid} @filtevents)) {
		my %fields;
		print "\"$ftimestamp\"$sep\"$feventid\"$sep\"$fcomputer\"$sep";
		foreach my $field (@{$xmls->{'EventData'}->[0]->{'Data'}}) {
			if (grep {$_ eq $field->{'Name'}} @filtfields) {
				$fields{$field->{'Name'}}=$field->{'content'};
				#print $field->{'Name'};
				#print "=";
				#print $field->{'content'};
				#print "\n";
			}
		}
		foreach my $field (@filtfields) {
			print "\"$fields{$field}\"$sep";
		}
		print "\n";
	}
	$event = $file->get_next_event();
};

$fh->close();
