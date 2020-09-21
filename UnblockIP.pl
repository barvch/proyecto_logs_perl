#!/bin/perl

##
# PBSI 14G
# Módulo: Programación con Perl
##

use strict;
use POSIX qw(strftime);

my $ip = $ARGV[0]; # IP a desbloquear
my $log = $ARGV[1]; # Bitácora a escribir
my $secs = $ARGV[2]; # Cantidad de segundos a esperar
my $bin = ($ip =~ /:/) ? "ip6tables" : "iptables"; # Binario a utilizar

sleep($secs);
system('sed -i "/^'.$ip.'$/d" BlockedIPs'); # Primer intento de eliminación
system("$bin -D INPUT -s ".$ip." -j DROP");
open FW, ">>$log" or die "No se pudo escribir en la bitácora";
print FW "UNBLOCKED - $ip - ".(strftime "%F %T", localtime)."\n"; # Bitácora
close(FW);
system('sed -i "/^'.$ip.'$/d" BlockedIPs'); # Segundo intento de eliminación
