use Data::Dumper;
use Apache::Log::Parser;

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
$bandera = 0; # Sirve para indicar si es la primera vez que se ingresa al bucle infinito
while(1) {
    if ($bandera == 0) { # Si es la primera vez que se ingresa al bucle
        $noLineasUltimoMonitoreo = `cat $rutaLog | wc | cut -d " " -f 6`; # Se calcula la contidad de lineas actuales del log a revisar
        chomp($noLineasUltimoMonitoreo);
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
        # En caso de encontrar nuevas líneas en el log
        $lineasPorRevisar = qx/tail -$lineasNuevas $rutaLog/; # Se leen las nuevas líneas encontradas en el log
        @lineas = split("\n", $lineasPorRevisar); # Se separa linea por linea
        $noLineasUltimoMonitoreo = $noLineasActuales; # Se actualiza el valor del total de líneas leídas en la última revisión
    }
    %ips = (); # Reset al hash que contiene el timestamp y el no. de veces que aparece
    %hostsEncontrados = (); # Hash que almacena cuáles IPs ya han pasado a la función de banneo
    foreach (@lineas) {
        $log = $parser->parse($_); # Se hace el parsing de la linea actual del log
        $timestamp = $log->{rhost} ." - " . $log->{time} . " - " . $log->{date} . "\n"; # Se genera un timestamp de la linea actual. [HOST - HORA - FECHA]
        # El timestamp sirve como llave para nuestro hash. El valor asociado a la llave, es el número de apariciones de esa llave dentro de las lineas que se leyeron del log.
        if (exists($ips{$timestamp})) { # Si ya existe esa llave dentro del hash, recuperamos el valor y se incrementa en uno
            $cont = $ips{$timestamp}; # Se recupera el no. de ocurrencias de ese timestamp hasta ahora
            if ($cont >= $valores{"attempts"}) {next;} # Si se trata de una timestamp que ya ha sido identificado, se skipea
            $cont++; # Se incrementa el valor en uno en caso de que no cumpla con la condición de arriba
            $ips{$timestamp} = $cont; # Se actualiza el valor dentro del hash
            if($ips{$timestamp} >= $valores{"attempts"}) { #Y ahora se revisa si el valor actualizado, es mayor o igual al tope de peticiones definidas en el archivo de configuaración
                if (exists($hostsEncontrados{$log->{rhost}})) { # Si existe dentro del hash la IP, ya ha sido banneada y no es necesario hacer algo
                    next;
                } else { # En caso de de que la IP no se encuentre dentro del hash
                    $hostsEncontrados{$log->{rhost}} = 1; # Se guarda la IP del host en el hash sólo como referencia para que no se repita
                    print("$log->{rhost}\n");
                    # Se manda a llamar la función para el banneo de la IP encontrada
                    #funcionBanIp($log->{rhost});
                } 
            }
        } else { # En caso de que se trate de un timestamp nuevo
            $ips{$timestamp} = 1; # Se registra dentro del hash y se le asigna 1 aparición
        }
    }
    sleep($valores{"time"}); # Se esperan n segundos para volver a revisar el log de apache.
}