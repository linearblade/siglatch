#!/usr/bin/perl
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin";
use grantLib;
use grantConfig;
use POSIX qw(strftime);

print "NUKING FROM ORBIT AND LETTING GOD SORT IT OUT\n";

# Parse context
my ($ip, $uid, $uname, $actcode, $actname, $encrypted, $b64payload) = @ARGV;
my $entry = parseEntry($ip, $uid, $uname, $actcode, $actname, $encrypted, $b64payload);

writeLog($grantConfig::grantLog, $entry);  

flushAll("flushed by $uname\@$ip");
