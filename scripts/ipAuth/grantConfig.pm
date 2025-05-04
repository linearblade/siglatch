package grantConfig;
use strict;
use warnings;
use Exporter 'import';
use File::Path qw(make_path);

our @EXPORT = qw(
    $logDir
    $grantTable
    $templateFile
    $outputScript
    $timeoutSeconds
    $grantLog
);


our $logDir         ;
our $stateDir       ;
our $grantLog       ;
our $grantTable     ;
our $templateFile   ;
our $outputScript   ;
our $timeoutSeconds ;


# 🔧 Shared config values
BEGIN {
    $logDir         = "/var/log/siglatch";
    $stateDir       = "/var/lib/siglatch";
    
    foreach my $dir ($logDir, $stateDir) {
	unless (-d $dir) {
	    make_path($dir) or die "Failed to create $dir: $!";
	}
    }
    $grantLog       = "$logDir/grant_log.json";
    $grantTable     = "$stateDir/grants.json";
    $templateFile   = "/etc/siglatch/scripts/ipAuth/config/boilerplate.txt";
    $outputScript   = "$stateDir/lastGrant.sh";
    $timeoutSeconds = 3600;  # 1 hour

}


1;
