#!/bin/perl

##
# PBSI 14G
# Módulo: Programación con Perl
##

use strict;

my $ip = $ARGV[0]; # IP a desbloquear
chomp($ip);
system('sed -i "/^'.$ip.'$/d" BlockedIPs');
system("iptables -D INPUT -s ".$ip." -j DROP");