use Data::Dumper;
use Apache::Log::Parser;

open (CONFIG_FILE, "servicio_eq2.conf");
@contenido = <CONFIG_FILE>;
%valores = ();
foreach (@contenido) {
    if (index($_, "#") != -1) { # Se omiten los comentarios del archivo de conf
        next;
    } else { # Se guarda en el hash, llave y valor
        @temp = split("=", $_);
        $valores{$temp[0]} = $temp[1];
    }
}
$parser = Apache::Log::Parser->new( fast => 1 ); # Se crea el parser
#$rutaLog = $valores{"log"}; # se usa la ruta del diccionario
%conteo = (); # Hash que tiene las veces que aparece un host en en log
$rutaLog = "ejemplo.log"; 
open(LOG_APACHE, $rutaLog);
@lineas = <LOG_APACHE>;
foreach (@lineas) {
    $log = $parser->parse($_);
    #print $log->{rhost}, "\n"; #=> remote host
    #print $log->{agent}, "\n"; #=> user agent
    #print $log->{time}, "\n";
    #print $log->{date}, "\n";
    if (exists($conteo{$log->{rhost}})){
        $cont = $conteo{$log->{rhost}};
        $cont++;
        $conteo{$log->{rhost}} = $cont;
    } else {
        $conteo{$log->{rhost}} = 1; 
    }
}
 print Dumper (\%conteo);