package grantLib;
use strict;
use warnings;
use Exporter 'import';


# Export only what we want public
#our @EXPORT_OK = qw(
our @EXPORT = qw(
    parseEntry
    writeLog
    readGrants
    removeFromIndex
    writeGrantIndex
    updateGrantIndex
    getValidIps
    writeFirewallScriptToString
    writeToFile
    logExpire
    getExpiredIps
    expireCron
    flushAll
);

use JSON;
use MIME::Base64 qw(encode_base64 decode_base64);
use Encode qw(is_utf8);
use POSIX qw(strftime);
use Time::Piece;
use File::Path qw(make_path);
use grantConfig;


sub parseEntry {
    my ($ip, $uid, $uname, $actcode, $actname, $encrypted, $b64payload) = @_;
    #my $is_ascii = ($comment =~ /^[\x00-\x7F]*$/);
    #my $is_null_terminated = ($comment =~ /\0$/);
    #my $unicode = 0;
    #my $b64 = 0;


    my $comment = '';
    my $b64 = 0;
    my $unicode = 0;


     # Decode payload

    my $decoded = decode_base64($b64payload) ;

    if (defined $decoded && $decoded ne '') {
	# Clean trailing junk
	$decoded =~ s/[\x00-\x1F]+$//;

	# Save a clean copy for base64 encoding later (if needed)
	my $clean = $decoded;
	
	# Internally ensure null-term
	$decoded .= "\0" unless $decoded =~ /\0$/;

	# Check if ASCII
	my $is_ascii = ($clean =~ /^[\x00-\x7F]*$/);

	if ($is_ascii) {
	    $comment = $decoded;    # keep original (with \0)
	} else {
	    $comment = encode_base64($clean, '');  # re-encode without added \0
	    $b64 = 1;
	}
    } else {
	$comment = '';
    }

    # Clean trailing nulls or other non-visible junk
    $comment =~ s/[\x00-\x1F]+$//;

    my %log = (
        ip        => $ip,
        user      => $uname,
	action    => $actname,
        comment   => $comment,
        timestamp => strftime('%Y-%m-%dT%H:%M:%SZ', gmtime),
        b64       => $b64,
	);
    return \%log;
}

sub writeLog{
    my ($logfile, $entry ) = @_;
    $entry->{unicode} = JSON::true if($entry->{b64});


    my $json = JSON->new->utf8->canonical->pretty->encode($entry);

    #my $logfile = "$FindBin::Bin/logs/grant_log.json";
    open my $fh, ">>", $logfile or die "Cannot open log file: $!";
    print $fh "$json\n";
    close $fh;
}

sub readGrants {
    my ($path) = @_;
    my $grants = {};

    if (-e $path) {
        open my $in, "<", $path or die "Can't read grant table: $path: $!";
        local $/;
        my $json = <$in>;
        close $in;

        $grants = eval { JSON->new->utf8->decode($json) } || {};
    }

    return $grants;
}

sub removeFromIndex{
    my( $grants ,$ip_to_revoke) = @_;
    # Remove the specified IP
    if (exists $grants->{$ip_to_revoke}) {
	delete $grants->{$ip_to_revoke};
	print "Revoked access for $ip_to_revoke\n";
    } else {
	print "No active grant found for $ip_to_revoke\n";
    }
}

sub writeGrantIndex {
    my ($file, $grants) = @_;
   # Rewrite grant table
    open my $out, ">", $file or die "Can't write updated grant table: $!";
    print $out JSON->new->utf8->pretty->canonical->encode($grants);
    close $out;
}

sub updateGrantIndex {
    my ($index_file, $entry) = @_;

    # Load existing table or create new one
    my $table = {};
    if (-e $index_file) {
        open my $in, "<", $index_file or die "Can't read index file: $!";
        local $/;  # Slurp mode
        my $json = <$in>;
        close $in;

        $table = eval { JSON->new->utf8->decode($json) } || {};
    }

    # Update the table using IP as the key
    my $ip = $entry->{ip};
    $table->{$ip} = $entry;

    # Write it back to disk
    writeGrantIndex($index_file,$table);
    return $table;
}




sub getValidIps {
    my ($grants, $timeout) = @_;
    my @allowed_ips;

    my $now = time;

    for my $ip (keys %$grants) {
        my $entry = $grants->{$ip};
        my $ts = eval { Time::Piece->strptime($entry->{timestamp}, "%Y-%m-%dT%H:%M:%SZ")->epoch };

        next unless defined $ts;
        next if ($now - $ts > $timeout);

        push @allowed_ips, $ip;
    }

    return \@allowed_ips;
}

sub writeFirewallScriptToString {
    my ($template_path, $grant_ips) = @_;

    open my $in, '<', $template_path or die "Can't read $template_path: $!";

    my $output = '';

    while (my $line = <$in>) {
        if ($line =~ /^__DATA__/) {
            $output .= "# BEGIN GRANTED DYNAMIC RULES\n";
            foreach my $ip (@$grant_ips) {
                $output .= "iptables -A INPUT -p TCP -s $ip/32 --dport 22 -j ACCEPT\n";
            }
            $output .= "# END GRANTED DYNAMIC RULES\n";
        } else {
            $output .= $line;
        }
    }

    close $in;
    return $output;
}

sub writeToFile {
    my ($file,$data) = @_;
    open my $fh, ">", $file or die $!;
    print $fh $data;
    close $fh;
    chmod 0755, $file;
}

sub logExpire {
    my ($ip, $comment) = @_;

    my %log = (
        ip        => $ip,
        comment   => $comment,
        timestamp => strftime('%Y-%m-%dT%H:%M:%SZ', gmtime),
        action    => 'expire_cron',
	);

    writeLog($grantConfig::grantLog, \%log);
}
sub logFlush {
    my ($ip, $comment) = @_;

    my %log = (
        ip        => $ip,
        comment   => $comment,
        timestamp => strftime('%Y-%m-%dT%H:%M:%SZ', gmtime),
        action    => 'flush_all',
	);

    writeLog($grantConfig::grantLog, \%log);
}
sub getExpiredIps {
    my ($grants, $timeoutSeconds) = @_;
    my $now = time;
    my @expired = ();

    for my $ip (keys %$grants) {
        my $entry = $grants->{$ip};
        my $ts = eval { Time::Piece->strptime($entry->{timestamp}, "%Y-%m-%dT%H:%M:%SZ")->epoch };
        next unless defined $ts;

        if ($now - $ts > $timeoutSeconds) {
            push @expired, $ip;
        }
    }

    return \@expired;
}

sub expireCron {
    my ($grants, $comment) = @_;
    my $expired_ips = getExpiredIps($grants, $grantConfig::timeoutSeconds);
    return unless @$expired_ips;

    foreach my $ip (@$expired_ips) {
        delete $grants->{$ip};
    }

    writeGrantIndex($grantConfig::grantTable, $grants);

    my $valid_ips = getValidIps($grants, $grantConfig::timeoutSeconds);
    my $script    = writeFirewallScriptToString($grantConfig::templateFile, $valid_ips);
    writeToFile($grantConfig::outputScript, $script);
    `$grantConfig::outputScript`;

    foreach my $ip (@$expired_ips) {
        logExpire($ip, $comment);
    }

    return $expired_ips;
}

sub flushAll{
    my $comment = shift;

    my $grants = readGrants($grantConfig::grantTable);


    foreach my $ip (keys %$grants) {
	logFlush($ip, $comment);
    }

    writeGrantIndex($grantConfig::grantTable, {});

    my $script = writeFirewallScriptToString($grantConfig::templateFile, []);
    writeToFile($grantConfig::outputScript, $script);
    `$grantConfig::outputScript`;
}

1;


