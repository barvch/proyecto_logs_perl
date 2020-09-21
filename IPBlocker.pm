#!/bin/perl

package IPBlocker;

##
# PBSI 14G
# Module: Programación con Perl
# Author: Alexis Brayan López Matías
##

use strict;
use warnings;
use POSIX qw(strftime);

# Constructor de la clase IPBlocker.
sub new {
  my $class = shift;
  my $self = {
    _blockTime => shift,  # Tiempo de bloqueo de IPs
    _logFile => shift,    # Bitácora a generar
  };
  # Logs y tiempo de bloqueo de 10 min por defecto
  $self->{_blockTime} = 10 unless $self->{_blockTime};
  $self->{_blockTime} = '/var/log/ipblocker.log' unless $self->{_logFile};

  bless $self, $class;
  return $self;
}

# Bloquea una dirección IP.
sub blockIP {
  my( $self, $ip ) = @_;
  open FWR, "+>>BlockedIPs" or die "No se pudo abrir el archivo con las IPs "
    ."bloqueadas";
  open FW1, ">>".$self->{_logFile} or die "No se pudo escribir en la bitácora";
  # IP no bloqueada
  if (!$self->isIPBlocked($ip)) {
    print FWR "$ip\n";
    system("iptables -A INPUT -s ".$ip." -j DROP");
    print FW1 "BLOCKED - $ip - ".(strftime "%F %T", localtime)."\n";
    my $secs = strftime "%S", localtime;
    system("echo 'perl UnblockIP.pl $ip ".$self->{_logFile}." $secs' | "
      ."at -M now +".$self->{_blockTime}." minutes >> /dev/null 2>&1");
  }
  close(FWR);
  close(FW1);
}

# Bloquea una lista de direcciones IP.
sub blockIPs {
  my( $self, @ips ) = @_;
  open FRW, "+>>BlockedIPs" or die "No se pudo abrir el archivo con las IPs "
    ."bloqueadas";
  open FW2, ">>".$self->{_logFile} or die "No se pudo escribir en la bitácora";
  # Procesamos qué IPs están o no bloqueadas
  my %checkedIPs = $self->isIPsBlocked(@ips);

  # Bloqueamos cada IP no bloqueada previamente
  foreach my $ip (@ips) {
    # IP no bloqueada
    if (!$checkedIPs{$ip}) {
      print FRW "$ip\n";
      system("iptables -A INPUT -s ".$ip." -j DROP");
      print FW2 "BLOCKED - $ip - ".(strftime "%F %T", localtime)."\n";
      my $secs = strftime "%S", localtime;
      system("echo 'perl UnblockIP.pl $ip ".$self->{_logFile}." $secs' | "
        ."at -M now +".$self->{_blockTime}." minutes >> /dev/null 2>&1");
    }
  }
  close(FRW);
  close(FW2);
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