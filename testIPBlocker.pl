#!/bin/perl

##
# PBSI 14G
# Módulo: Programación con Perl
##

use strict;
use lib './';
use IPBlocker;
use feature qw(say);
use Data::Printer;

my $blockTime = 1; # 1 min de bloqueo
my $ipBlocker = new IPBlocker($blockTime, '/var/log/apache2_eq2.log');

# Bloqueamos múltiples IPs
$ipBlocker->blockIPs(@{ [ '192.168.145.211', '192.168.145.212',
  '192.168.145.213' ] });

# Bloqueamos una sola IP
$ipBlocker->blockIP('192.168.145.214');

say "Tiempo de bloqueo: ", $ipBlocker->getBlockTime(), " minuto(s).";

print "127.0.0.1 is ";
print "not " if (!$ipBlocker->isIPBlocked('127.0.0.1'));
print "blocked.\n";

print "192.168.145.213 is ";
print "not " if (!$ipBlocker->isIPBlocked('192.168.145.213'));
print "blocked.\n";