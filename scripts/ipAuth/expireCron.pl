#!/usr/bin/perl
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin";
use grantLib;
use grantConfig;

my $grants = readGrants($grantConfig::grantTable);
expireCron($grants, "expired by cron");
