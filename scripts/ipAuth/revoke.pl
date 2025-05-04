#!/usr/bin/perl
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin";
use grantLib;
use grantConfig;

print "RUNNING REVOKE\n";

# Input: full payload like grant.pl
my ($ip, $uid, $uname, $actcode, $actname, $encrypted, $b64payload) = @ARGV;

if (@ARGV < 7) {
    die "Usage: $0 <ip> <user_id> <username> <action_code> <action_name> <encrypted> <payload_base64>\n";
}

# Step 1: Parse payload to log entry
my $entry = parseEntry($ip, $uid, $uname, $actcode, $actname, $encrypted, $b64payload);


# Step 2: Write audit log entry
writeLog($grantConfig::grantLog, $entry);  # Add this to grantConfig.pm as $grantLog if you like

# Step 3: Remove from index
my $grants = readGrants($grantConfig::grantTable);
removeFromIndex($grants, $ip);
writeGrantIndex($grantConfig::grantTable, $grants);

# Step 5: Rebuild and apply firewall
my $valid_ips = getValidIps($grants, $grantConfig::timeoutSeconds);
my $script = writeFirewallScriptToString($grantConfig::templateFile, $valid_ips);
writeToFile($grantConfig::outputScript, $script);
`$grantConfig::outputScript`;
