#!/usr/bin/perl -w
use strict;
use POSIX qw(WNOHANG);
use Getopt::Long;
use Time::HiRes;

#+++
# rblchk.pl
#   Multi-threaded RBL checker
#   (c) Scott Brynen - 2016
#
#---


my @defaultrbls = qw(zen.spamhaus.org b.barracudacentral.org cbl.abuseat.org bl.spamcop.net
                     dnsbl.sorbs.net hostkarma.junkemailfilter.com=127.0.0.2);
my $opttimeout = 12;  # timeout for a DNS request
my $optthreads = 100; # max # of threads
my @ips;       # ips from command line
my @optrbls;   # rbls from the command line
my @todo;      # "ip rbl" list of items to check
my %rblcheck;  # rblcheck{"ip rbl"} = STATUS
my %pidlookup; # taskarray{PID} = "ip rbl";
my %pidstart;  # pidstart{PID} = time
my %textout = (0 => 'ok', 1 => 'LISTED', 2 => 'TIMEOUT');
my %totals = (0 => 0, 1 => 0, 2 => 0); # count of oks, listeds, timeouts
my $nthread = 0; # current number of threads
my $titlesdone = 0;  #have we written the titles?
my @rblfails;    # stores nagios RBL failures
my $opthelp;
my $optquiet = 0; #  only output failures
my $optnagios = 0; # nagios mode flag
my $colwidth = 12; # column width, 12 works well


#+++
# usage()
#  output usage info, and exit
#---
sub usage() {
    print STDERR "usage: $0 [options] <ip> [<ip> ..]\n\n";
    print STDERR "checks one or more IP or ranges against a set of RBLs using parallel DNS requests\n\n";
    print STDERR "IPs can be specified as single IPs, ranges (192.168.1.1-10), or netblocks (192.168.1.0/26)\n\n";
    print STDERR "Options:\n";
    print STDERR "  --rbl        RBL to check against; multiple RBLs are separated with commas.\n";
    print STDERR "               Optionally you can search only for a specific result in the form\n";
    print STDERR "               somerbl.org=127.0.0.1  If no RBLs are specified, the default RBLs are:";
    print STDERR (($_ % 3) ? ",  ":"\n                    "). $defaultrbls[$_] foreach (0 .. $#defaultrbls);
    print STDERR "\n  --timeout n  Timeout for DNS requests (default=$opttimeout)\n";
    print STDERR "  --threads n  Maximum number of simultaneous threads (default=$optthreads)\n";
    print STDERR "  --quiet      Only output IPs where there is a listing\n";
    print STDERR "  --nagios     Act as a nagios check.  Outputs nagios compatible results and exit codes\n\n";
    print STDERR "exit codes:\n";
    print STDERR "  exits 0 if all IPs are not listed, or exits 1 if any IP is listed\n";
    print STDERR "  in nagios mode, exits OK (0) for no listings, or CRITICAL (2) for any IP listed\n";
    exit 3;
}

#+++
# center(str, width)
#   center and chop str to width
#---
sub center {
    my $orig = shift;
    my $width = shift;
    while (length($orig) < $width) {
        $orig = ' '. $orig. ' ';
    }
    return substr($orig, 0, $width);
}

#+++
# checkrbl(ip, rbl, val)
#  check if ip is on rbl.  Optionally check to see if it exactly matches val
#---
sub checkrbl {
    my ($ip,$rbl,$iptest) = @_;
    my $chk =  join('.', reverse split(/\./, $ip)). ".$rbl";
    $chk .= '.'  if ($chk !~ /\.$/); #prevent libdns from adding localdomain
    my ($name,$aliases,$addrtype,$length,@addrs) = gethostbyname($chk);
    if (defined($name) && (!$iptest || ($iptest eq join('.', unpack("C4", $addrs[0]))) )) {
        return 1; #This is on an RBL
    } else {
        return 0; #not listed
    }
}


#+++
# main()
#

#
# parse the command line options
GetOptions("rbl|r=s"     => \@optrbls,
           "timeout|t=i" => \$opttimeout,
           "threads|n=i" => \$optthreads,
           "quiet|q"     => \$optquiet,
           "nagios"      => \$optnagios,
           "help|h|?"    => \$opthelp);
usage if ($opthelp);
if (@optrbls) {
    @optrbls = split(',', join(',', @optrbls));  # allow either rbl=a,b,c or rbl=a rbl=b
} else {
    @optrbls = @defaultrbls;
}

#
# build the list of IPs to check from the command line
foreach (@ARGV) {
    if (/^\d+\.\d+\.\d+\.\d+$/) { # 192.168.1.1 format
        push @ips, $_;
    } elsif (/^(\d+\.\d+\.\d+\.)(\d+)-(\d+)$/) { # 192.168.1.1-10 format
        push @ips, $1.$_   foreach ($2 .. $3);
    } elsif (/^(\d+\.\d+\.\d+\.\d+)\/(\d+)$/) { # 192.168.1.0/24 format
        my $base = unpack('N', (pack 'C4', split(/\./, $1)));
        my $mask = 0xffffffff - (2**(32-$2) - 1);
        push @ips, join('.', unpack('C4', pack('N', ($base & $mask) + $_)))   foreach (0 .. (2**(32-$2) -1));
    } elsif (/^[0-9a-zA-Z.-]+$/) { # needs resolving
        my (@resolved) = gethostbyname($_);
        if (@resolved) {
            foreach (4 .. $#resolved) {
                push @ips, join('.', unpack("C4", $resolved[$_]));
            }
        } else {
            print STDERR "ERROR: unable to resolve $_\n";
            exit 3;
        }
    } else {
        print STDERR "ERROR: Invalid IP Address $_\n";
        exit 3;
    }
}

#
if (!@ips) {
    print STDERR "ERROR: no ips specified\n\n";
    exit 3;
}

#
# make the todolist IP-RBL
foreach my $ip (@ips) {
    foreach my $rbl (@optrbls) {
        push @todo, "$ip $rbl";
    }
}

#
# main loop
while (@todo || $nthread > 0) {
    # create threads if we have room;
    while (@todo && ($nthread < $optthreads)) {
        my $tocheck = $todo[-1];
        my $pid = fork();
        last unless defined $pid;  # skip parent/child code if fork failed
        if ($pid) { #parent
            $nthread++;
            $pidlookup{$pid} = $tocheck;
            $pidstart{$pid} = time();
            pop @todo; # it started ok, remove from the todo
        } else { #child
            my ($ip,$rbl,$match) = split(/[ =:]/, $tocheck);
            exit checkrbl($ip, $rbl, $match);
        }
    }
    # kill timed out threads
    foreach (keys %pidstart) {
        if (time() > $pidstart{$_} + $opttimeout) {
            kill 9, $_;
        }
    }
    # wait a bit for tasks to complete (200mS)
    Time::HiRes::usleep(200000);
    # processed any completed & killed threads
    my $pid = waitpid(-1, WNOHANG);
    while ($pid > 0) { # any finished processes?
        my $childexit = $?;
        if ( ($childexit & 0xff) == 9) {
            $rblcheck{$pidlookup{$pid}} = 2;  #kill -9'd = timeout
        } else {
            $rblcheck{$pidlookup{$pid}} = $childexit >> 8;
        }
        delete $pidstart{$pid};
        delete $pidlookup{$pid};
        $nthread--;
        $pid = waitpid(-1, WNOHANG);
    }
}

#
# look at the results
foreach my $ip (@ips) {
    my $thisline;
    my $rblthisip = 0;
    # check the results for this IP
    foreach my $rbl (@optrbls) {
        if ($rblcheck{"$ip $rbl"} == 1) {
            $rblthisip = 1;
            push @rblfails, "$ip found on $rbl" if ($optnagios);
        }
        $thisline .= center($textout{$rblcheck{"$ip $rbl"}}, $colwidth)  if (!$optnagios);
        $totals{$rblcheck{"$ip $rbl"}}++;
    }
    # and output the results for this IP (if necessary)
    if (!$optnagios && (!$optquiet || $rblthisip)) {
        if (!$titlesdone) { # write the titles for the 1st time
            my @titles = (' 'x(16 - $colwidth/2), # 16 is IP width
                          ' 'x(16 + $colwidth/2),
                          '-'x(16 + $colwidth * (scalar @optrbls + 0.5)));
            foreach (my $i = 0; $i < scalar @optrbls; $i++) { # stagger titles over two lines
                $titles[$i % 2] .= center($optrbls[$i], 2 * $colwidth);
            }
            print join("\n", @titles). "\n";
            $titlesdone = 1;
        }
        printf("%-15s %s\n", $ip, $thisline);
    }
}

#
# final exit for nagios
if ($optnagios) {
    if ($totals{1} > 0) {
        print "CRITICAL: $totals{1} IP/RBL match". ($totals{1} > 1 ? "es":"");
        print "|ok=$totals{0} fail=$totals{1} timeout=$totals{2}\n";
        print join ("\n", @rblfails). "\n";
        exit 2; #nagios CRITICAL
    } else {
        print "OK: no hosts found on RBLs (ok=$totals{0}, timeout=$totals{2})";
        print "|ok=$totals{0} fail=$totals{1} timeout=$totals{2}\n";
        exit 0;
    }
}
#
# final exit for normal execution
else {
    exit (($totals{1} > 0) ? 1 : 0);
}
