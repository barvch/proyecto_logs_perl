use Data::Dumper;
use Apache::Log::Parser;
use Time::Local;

# Lectura de los valores del archivo de configuración

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

# Variables globales
$parser = Apache::Log::Parser->new( fast => 1 ); # Se crea el parser para los logs de Apache/Nginx
#$rutaLog = $valores{"log"}; # se usa la ruta del diccionario
$rutaLog = "ejemplo.log";
#$rutaLog = "/var/log/apache2/access.log.1";
$bandera = 0; # Sirve para indicar si es la primera vez que se ingresa al bucle infinito
while(1) {
    if ($bandera == 0) { # Si es la primera vez que se ingresa al bucle
        $noLineasUltimoMonitoreo = `cat $rutaLog | wc | cut -d " " -f 6`; # Se calcula la contidad de lineas actuales del log a revisar
        chomp($noLineasUltimoMonitoreo);
        #print("Se han encontrado $noLineasUltimoMonitoreo lineas en el log.\n");
        $lineasPorRevisar = qx/tail -$noLineasUltimoMonitoreo $rutaLog/; # Se leen todas las lineas del log
        @lineas = split("\n", $lineasPorRevisar); # Se separa linea por linea
        $bandera = 1; # Se actualiza el valor de la bandera para que no caiga en este if nunca más
    } else {
        $noLineasActuales = `cat $rutaLog | wc | cut -d " " -f 6`; # Se leen todas las lineas del log actualizado
        chomp($noLineasActuales);
        $lineasNuevas =  $noLineasActuales - $noLineasUltimoMonitoreo; # Se calculan las nuevas lineas que han sido generadas en el log desde la ultima revisión
        if ($lineasNuevas == 0) { # Si no hay diferencia, simplemente se espera para la siguiente revisión
            #print ("No se han encontrado nuevos regitros dentro del log, esperando cambios...\n");
            sleep($valores{"time"});
            next;
        }
        #print("Se han encontrado $lineasNuevas nuevas lineas dentro del log\n");
        # En caso de encontrar nuevas líneas en el log
        $lineasPorRevisar = qx/tail -$lineasNuevas $rutaLog/; # Se leen las nuevas líneas encontradas en el log
        @lineas = split("\n", $lineasPorRevisar); # Se separa linea por linea
        $noLineasUltimoMonitoreo = $noLineasActuales; # Se actualiza el valor del total de líneas leídas en la última revisión
    }
    open(LISTA, "+>", "ips.txt"); # Se abre el archivo donde se almacenarán las IPs a bloquear en modo de sobre escritura
    %ips = (); # Reset al hash que contiene el timestamp y el no. de veces que aparece
    foreach (@lineas) {
        $log = $parser->parse($_); # Se hace el parsing de la linea actual del log
        $timestamp = $log->{rhost} ." - " . $log->{time} . " - " . $log->{date} . "\n"; # Se genera un timestamp de la linea actual. [HOST - HORA - FECHA]
        # El timestamp sirve como llave para nuestro hash. El valor asociado a la llave, es el número de apariciones de esa llave dentro de las lineas que se leyeron del log.
        if (exists($ips{$timestamp})) { # Si ya existe esa llave dentro del hash, recuperamos el valor y se incrementa en uno
            $cont = $ips{$timestamp};
            if ($cont >= $valores{"attempts"}) {next;} # Si se trata de una timestamp que ya ha sido identificado, se skipea
            $cont++; # Se incrementa el valor en uno
            $ips{$timestamp} = $cont; # Se actualiza el valor dentro del hash
            if($ips{$timestamp} >= $valores{"attempts"}) { #Y se revisa si el valor actualizado, es mayor o igual al tope de peticiones definidas en el archivo de configuaración
                print LISTA ("$timestamp"); # En caso de que sí, se escribe la IP a bloquear dentro del archivo
            }
        } else { # En caso de que se trate de un timestamp nuevo
            $ips{$timestamp} = 1; # Se registra dentro del hash y se le asigna 1 aparición
        }
    }
    print("Se ha actualizado la lista de IP's por bloquear\n");
    close(LISTA); # Se cierra el archivo ya con las IPs escritas.
    sleep($valores{"time"}); # Se esperan n segundos para volver a revisar el log de apache.
}