#!/bin/perl

package IPBlocker;

##
# PBSI 14G
# Module: Programación con Perl
# Author: Alexis Brayan López Matías
##

use strict;
use warnings;
use threads;
use Data::Printer;
use POSIX qw(strftime);

# Constructor de la clase IPBlocker.
sub new {
  my $class = shift;
  my $self = {
    _blockTime => shift,  # Tiempo de bloqueo de IPs
  };
  $self->{_blockTime} = 10 unless $self->{_blockTime}; # 10 min por defecto

  bless $self, $class;
  return $self;
}

# Bloquea una lista de direcciones IP.
sub blockIPs {
  my( $self, @ips ) = @_;
  open FRW, "+>>BlockedIPs" or die "No se pudo abrir el archivo con las IPs "
    ."bloqueadas";
  # Obtenemos lista de IPs
  my @hosts = map { ${ $_ }{ip} } @ips;
  # Procesamos qué IPs están o no bloqueadas
  my %checkedIPs = $self->isIPsBlocked(@hosts);

  # Bloqueamos cada IP no bloqueada previamente
  foreach (@ips) {
    my $ip = ${ $_ }{ip};
    # IP no bloqueada
    if (!$checkedIPs{$ip}) {
      print FRW "$ip\n";
      system("iptables -A INPUT -s ".$ip." -j DROP");
      #my $unblockEpoch = ${ $_ }{time} + ($self->{_blockTime} * 60);
      #my $mins = $self->{_blockTime} * 60;
      #my $unblockTime = strftime "%R.%S", localtime($unblockEpoch);
      system("echo 'perl UnblockIP.pl $ip' | at now -M +"
        .$self->{_blockTime}." minutes >> /dev/null 2>&1");
    }
  }
  close(FRW);
}

# Retorna un diccionario indicando cuáles direccions IP se encuentran
# bloqueadas.
sub isIPsBlocked {
  my( $self, @ips ) = @_;
  open FR, "<BlockedIPs" or die "No se pudo abrir el archivo con las IPs "
    ."bloqueadas";
  # Crea un hash con cada IP indicada como no bloqueada
  my %blockedIPs = map { $_ => 0 } @ips;
  # Iteramos el archivo en búsqueda de IPs bloqueadas
  while (my $line = <FR>) {
    chomp($line);
    foreach (@ips) {
      if ($line =~ /^$_$/) {
        $blockedIPs{$_} = 1;
        last;
      }
    }
  }
  close(FR);
  return %blockedIPs;
}

# Determina si una dirección IP se encuentra bloqueada
sub isIPBlocked {
  my( $self, $ip ) = @_;
  open FR, "<BlockedIPs" or die "No se pudo abrir el archivo con las IPs "
    ."bloqueadas";
  # Iteramos el archivo en búsqueda de IPs bloqueadas
  while (<FR>) {
    return 1 if ($_ =~ /$ip/);
  }
  return 0;
}

# Retorna el tiempo de bloqueo de IPs en minutos.
sub getBlockTime {
  my( $self ) = @_;
  return $self->{_blockTime};
}

1;