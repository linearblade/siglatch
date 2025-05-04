#!/usr/bin/perl
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin";
use grantLib;
use grantConfig;

print "RUNNING GRANT\n";

# Step 0: Full argument check
my ($ip, $uid, $uname, $actcode, $actname, $encrypted, $b64payload) = @ARGV;

if (@ARGV < 7) {
    die "Usage: $0 <ip> <user_id> <username> <action_code> <action_name> <encrypted> <payload_base64>\n";
}

# Step 1: Parse grant entry
my $entry = parseEntry($ip, $uid, $uname, $actcode, $actname, $encrypted, $b64payload);


# Step 2: Write audit log and update index
writeLog($grantConfig::grantLog, $entry);
my $grants = updateGrantIndex($grantConfig::grantTable, $entry);

# Step 3: Filter valid IPs and write firewall script
my $valid_ips = getValidIps($grants, $grantConfig::timeoutSeconds);
my $script = writeFirewallScriptToString($grantConfig::templateFile, $valid_ips);
writeToFile($grantConfig::outputScript, $script);

# Step 4: Apply rules
`$grantConfig::outputScript`;
