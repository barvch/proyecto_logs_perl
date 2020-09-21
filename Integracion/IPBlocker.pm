#!/bin/perl

package IPBlocker;

##
# PBSI 14G
# Module: Programación con Perl
# Author: Alexis Brayan López Matías
##

=encoding UTF-8

=head1 NAME

IPBlocker - Módulo que bloquea direcciones IP.

=head1 SYNOPSIS

  use IPBlocker;
  my $blockTime = 1; # 1 min de bloqueo
  my $ipBlocker = new IPBlocker($blockTime, '/var/log/apache2_eq2.log');

  #Bloqueamos múltiples IPs
  $ipBlocker->blockIPs(@{ [ '192.168.145.211', '192.168.145.212',
    '192.168.145.213' ] });

  # Bloqueamos una sola IP
  $ipBlocker->blockIP('192.168.145.214');

=head1 DESCRIPTION

Este módulo permite bloquear direcciones IP y generar registros en la bitácora
especificada durante la creación del objeto.

=head2 Methods

=over 12

=item C<new>

Retorna un nuevo objeto IPBlocker.

=item C<blockIP>

Bloquea una dirección IP.

=item C<blockIPs>

Bloquea una lista de direcciones IP.

=item C<areIPsBlocked>

Verifica si una lista de direcciones IP están o no bloqueadas.

=item C<isIPBlocked>

Verifica si una dirección IP está bloqueada.

=item C<getBlockTime>

Retorna el tiempo de bloqueo utilizado.

=back

=head1 LICENSE

Este módulo fue creado bajo una licencia artística.
Ver L<perlartistic>.

=head1 AUTHOR

Equipo2 - PBSI 14G

=head1 SEE ALSO

L<UnblockIP>

=cut

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

sub DEMOLISH {
  my ($self) = @_;
  open FW1, ">>".$self->{_logFile} or die "No se pudo escribir en la bitácora";
  print FW1 "SERVICIO DETENIDO ".(strftime "%F %T", localtime)."\n";
  close(FW1);
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
  my %checkedIPs = $self->areIPsBlocked(@ips);

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
sub areIPsBlocked {
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