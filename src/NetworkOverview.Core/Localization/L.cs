using System.Globalization;

namespace NetworkOverview.Core.Localization;

/// <summary>UI strings in German, English, Spanish and French.</summary>
public static class L
{
    public static readonly string[] Languages = { "de", "en", "es", "fr" };
    static int lang = Detect();

    public static string Current => Languages[lang];

    static int Detect()
    {
        var two = CultureInfo.CurrentUICulture.TwoLetterISOLanguageName;
        int i = Array.IndexOf(Languages, two);
        return i >= 0 ? i : 1;
    }

    /// <summary>"system" or empty selects the Windows display language (English if unsupported).</summary>
    public static void SetLanguage(string? code)
    {
        int i = string.IsNullOrEmpty(code) || code == "system" ? Detect() : Array.IndexOf(Languages, code);
        lang = i >= 0 ? i : 1;
    }

    public static string T(string key) => Table.TryGetValue(key, out var v) ? v[lang] : key;
    public static string T(string key, params object[] args) => string.Format(CultureInfo.CurrentCulture, T(key), args);

    // key -> { de, en, es, fr }
    public static readonly Dictionary<string, string[]> Table = new()
    {
        ["AppTitle"] = new[] { "Netzwerkübersicht", "Network Overview", "Vista general de la red", "Vue d’ensemble du réseau" },
        ["Adapter"] = new[] { "Netzwerkadapter:", "Network adapter:", "Adaptador de red:", "Carte réseau :" },
        ["Refresh"] = new[] { "Aktualisieren", "Refresh", "Actualizar", "Actualiser" },
        ["Cancel"] = new[] { "Abbrechen", "Cancel", "Cancelar", "Annuler" },
        ["Settings"] = new[] { "Einstellungen …", "Settings …", "Configuración …", "Paramètres …" },
        ["Log"] = new[] { "Protokoll …", "Log …", "Registro …", "Journal …" },
        ["SaveImage"] = new[] { "Als Bild speichern …", "Save as image …", "Guardar como imagen …", "Enregistrer comme image …" },
        ["ZoomIn"] = new[] { "Vergrößern", "Zoom in", "Ampliar", "Zoom avant" },
        ["ZoomOut"] = new[] { "Verkleinern", "Zoom out", "Reducir", "Zoom arrière" },

        ["StatusPing"] = new[] { "Pinge Subnetz an …", "Pinging subnet …", "Haciendo ping a la subred …", "Ping du sous-réseau …" },
        ["StatusOpenWrt"] = new[] { "Frage OpenWrt ab: {0}", "Querying OpenWrt: {0}", "Consultando OpenWrt: {0}", "Interrogation d’OpenWrt : {0}" },
        ["StatusNsdp"] = new[] { "Suche Netgear-Switches (NSDP) …", "Looking for Netgear switches (NSDP) …", "Buscando switches Netgear (NSDP) …", "Recherche de switchs Netgear (NSDP) …" },
        ["StatusMdns"] = new[] { "Frage mDNS-Dienste ab …", "Querying mDNS services …", "Consultando servicios mDNS …", "Interrogation des services mDNS …" },
        ["StatusSsdp"] = new[] { "Frage UPnP-Geräte (SSDP) ab …", "Querying UPnP devices (SSDP) …", "Consultando dispositivos UPnP (SSDP) …", "Interrogation des appareils UPnP (SSDP) …" },
        ["StatusWaitIp"] = new[] { "Warte auf eine IPv4-Adresse für „{0}“ …", "Waiting for an IPv4 address on \"{0}\" …", "Esperando una dirección IPv4 en «{0}» …", "Attente d’une adresse IPv4 sur «\u00A0{0}\u00A0» …" },
        ["WarnNoIPv4"] = new[] { "„{0}“ hat keine gültige IPv4-Adresse – OpenWrt, NSDP, mDNS und SSDP wurden übersprungen.", "\"{0}\" has no valid IPv4 address – OpenWrt, NSDP, mDNS and SSDP were skipped.", "«{0}» no tiene una dirección IPv4 válida: se omitieron OpenWrt, NSDP, mDNS y SSDP.", "«\u00A0{0}\u00A0» n’a pas d’adresse IPv4 valide – OpenWrt, NSDP, mDNS et SSDP ont été ignorés." },
        ["WarnOpenWrt"] = new[] { "OpenWrt nicht erreichbar: {0} – WLAN-Geräte dieser Zugangspunkte fehlen.", "OpenWrt unreachable: {0} – Wi-Fi devices of these access points are missing.", "OpenWrt inaccesible: {0}: faltan los dispositivos Wi-Fi de estos puntos de acceso.", "OpenWrt injoignable\u00A0: {0} – les appareils Wi-Fi de ces points d’accès manquent." },
        ["WarnNonObservers"] = new[] { "Diese LLTD-Responder empfangen keine Testrahmen und dienen nur als Sender: {0}", "These LLTD responders do not receive test frames and are only used as senders: {0}", "Estos respondedores LLTD no reciben tramas de prueba y solo se usan como emisores: {0}", "Ces répondeurs LLTD ne reçoivent pas les trames de test et servent uniquement d’émetteurs\u00A0: {0}" },
        ["IpOutsideNetwork"] = new[] { "IP-Adresse {0} liegt außerhalb des eigenen Netzes (Werkseinstellung? DHCP prüfen)", "IP address {0} is outside the own network (factory default? check DHCP)", "La dirección IP {0} está fuera de la red propia (¿valor de fábrica? revisar DHCP)", "L’adresse IP {0} est hors du réseau (valeur d’usine\u00A0? vérifier le DHCP)" },
        ["OptSsdp"] = new[] { "UPnP-Geräte per SSDP abfragen", "Query UPnP devices via SSDP", "Consultar dispositivos UPnP mediante SSDP", "Interroger les appareils UPnP via SSDP" },
        ["StatusArp"] = new[] { "Lese ARP-Tabelle …", "Reading ARP table …", "Leyendo la tabla ARP …", "Lecture de la table ARP …" },
        ["StatusDiscover"] = new[] { "Sende LLTD-Discover und warte auf Antworten …", "Sending LLTD Discover, waiting for replies …", "Enviando LLTD Discover, esperando respuestas …", "Envoi de LLTD Discover, attente des réponses …" },
        ["StatusRound"] = new[] { "Topologietest {0} von {1} …", "Topology test {0} of {1} …", "Prueba de topología {0} de {1} …", "Test de topologie {0} sur {1} …" },
        ["StatusEvaluate"] = new[] { "Werte aus und löse Namen auf …", "Evaluating and resolving names …", "Evaluando y resolviendo nombres …", "Analyse et résolution des noms …" },
        ["StatusCancelling"] = new[] { "Breche ab …", "Cancelling …", "Cancelando …", "Annulation …" },
        ["Summary"] = new[] { "{0} Geräte per LLTD, {1} Switches, {2} Geräte ohne Position.", "{0} devices via LLTD, {1} switches, {2} devices without position.", "{0} dispositivos por LLTD, {1} switches, {2} dispositivos sin posición.", "{0} appareils via LLTD, {1} switchs, {2} appareils sans position." },
        ["NpcapMissingShort"] = new[] { "Npcap fehlt – keine LLTD-Daten.", "Npcap missing – no LLTD data.", "Falta Npcap: sin datos LLTD.", "Npcap absent – pas de données LLTD." },
        ["LltdError"] = new[] { "LLTD-Fehler: {0}", "LLTD error: {0}", "Error de LLTD: {0}", "Erreur LLTD : {0}" },
        ["RunAsAdmin"] = new[] { "(Als Administrator starten?)", "(Run as administrator?)", "(¿Ejecutar como administrador?)", "(Exécuter en tant qu’administrateur ?)" },
        ["Partial"] = new[] { "Topologietest abgebrochen oder Zeitlimit erreicht – Ergebnis unvollständig.", "Topology test cancelled or time limit reached – result incomplete.", "Prueba de topología cancelada o límite de tiempo alcanzado: resultado incompleto.", "Test de topologie annulé ou délai atteint – résultat incomplet." },
        ["OpenWrtUnreachable"] = new[] { "{0} OpenWrt-Gerät(e) nicht erreichbar (siehe Protokoll).", "{0} OpenWrt device(s) unreachable (see log).", "{0} dispositivo(s) OpenWrt inaccesible(s) (ver registro).", "{0} appareil(s) OpenWrt injoignable(s) (voir le journal)." },
        ["NoAdapter"] = new[] { "Kein aktiver Netzwerkadapter gefunden.", "No active network adapter found.", "No se encontró ningún adaptador de red activo.", "Aucune carte réseau active trouvée." },
        ["NpcapMissingDialog"] = new[]
        {
            "Npcap wurde nicht gefunden.\n\nOhne Npcap können keine LLTD-Pakete gesendet und empfangen werden. Angezeigt werden dann nur Geräte aus ARP-Tabelle, OpenWrt, NSDP und mDNS, ohne Netzwerkaufbau.\n\nDownload-Seite von Npcap öffnen?",
            "Npcap was not found.\n\nWithout Npcap no LLTD frames can be sent or received. Only devices from the ARP table, OpenWrt, NSDP and mDNS are shown, without topology.\n\nOpen the Npcap download page?",
            "No se encontró Npcap.\n\nSin Npcap no se pueden enviar ni recibir tramas LLTD. Solo se muestran los dispositivos de la tabla ARP, OpenWrt, NSDP y mDNS, sin topología.\n\n¿Abrir la página de descarga de Npcap?",
            "Npcap est introuvable.\n\nSans Npcap, aucune trame LLTD ne peut être envoyée ni reçue. Seuls les appareils de la table ARP, d’OpenWrt, de NSDP et de mDNS sont affichés, sans topologie.\n\nOuvrir la page de téléchargement de Npcap ?",
        },
        ["Saved"] = new[] { "Gespeichert: {0}", "Saved: {0}", "Guardado: {0}", "Enregistré : {0}" },
        ["ImageFilter"] = new[] { "PNG-Bild (*.png)|*.png", "PNG image (*.png)|*.png", "Imagen PNG (*.png)|*.png", "Image PNG (*.png)|*.png" },
        ["ImageFileName"] = new[] { "Netzwerkuebersicht", "NetworkOverview", "VistaRed", "VueReseau" },

        ["ColName"] = new[] { "Name", "Name", "Nombre", "Nom" },
        ["ColIPv4"] = new[] { "IPv4", "IPv4", "IPv4", "IPv4" },
        ["ColMac"] = new[] { "MAC", "MAC", "MAC", "MAC" },
        ["ColVendor"] = new[] { "Hersteller", "Vendor", "Fabricante", "Fabricant" },
        ["ColType"] = new[] { "Typ", "Type", "Tipo", "Type" },
        ["ColMedium"] = new[] { "Medium", "Medium", "Medio", "Support" },
        ["ColLink"] = new[] { "Verbindung", "Link", "Enlace", "Liaison" },
        ["ColSsid"] = new[] { "SSID", "SSID", "SSID", "SSID" },
        ["ColLltd"] = new[] { "LLTD", "LLTD", "LLTD", "LLTD" },
        ["ColConnectedTo"] = new[] { "Verbunden mit", "Connected to", "Conectado a", "Connecté à" },

        ["ThisComputer"] = new[] { "Dieser Computer", "This computer", "Este equipo", "Cet ordinateur" },
        ["Gateway"] = new[] { "Gateway", "Gateway", "Puerta de enlace", "Passerelle" },
        ["Model"] = new[] { "Modell: {0}", "Model: {0}", "Modelo: {0}", "Modèle : {0}" },
        ["Vendor"] = new[] { "Hersteller: {0}", "Vendor: {0}", "Fabricante: {0}", "Fabricant : {0}" },
        ["Type"] = new[] { "Typ: {0}", "Type: {0}", "Tipo: {0}", "Type : {0}" },
        ["Medium"] = new[] { "Medium: {0}", "Medium: {0}", "Medio: {0}", "Support : {0}" },
        ["Link"] = new[] { "Verbindung: {0}", "Link: {0}", "Enlace: {0}", "Liaison : {0}" },
        ["Signal"] = new[] { "Signal: {0}", "Signal: {0}", "Señal: {0}", "Signal : {0}" },
        ["Ports"] = new[] { "Ports (Nr:Tempo): {0}", "Ports (no:speed): {0}", "Puertos (n.º:velocidad): {0}", "Ports (n°:débit) : {0}" },
        ["SeenAt"] = new[] { "Gesehen an: {0}", "Seen at: {0}", "Visto en: {0}", "Vu sur : {0}" },
        ["ConnectedTo"] = new[] { "Verbunden mit: {0}", "Connected to: {0}", "Conectado a: {0}", "Connecté à : {0}" },
        ["Services"] = new[] { "mDNS-Dienste: {0}", "mDNS services: {0}", "Servicios mDNS: {0}", "Services mDNS : {0}" },
        ["InferredSwitch"] = new[] { "Per LLTD-Test erkannter Switch ({0} Responder dahinter)", "Switch detected by LLTD tests ({0} responders behind it)", "Switch detectado por pruebas LLTD ({0} respondedores detrás)", "Switch détecté par les tests LLTD ({0} répondeurs derrière)" },
        ["Inferred"] = new[] { "(abgeleitet, nicht direkt erkannt)", "(inferred, not detected directly)", "(deducido, no detectado directamente)", "(déduit, non détecté directement)" },
        ["LltdYes"] = new[] { "LLTD: ja", "LLTD: yes", "LLTD: sí", "LLTD : oui" },
        ["LltdNo"] = new[] { "LLTD: nein", "LLTD: no", "LLTD: no", "LLTD : non" },
        ["Yes"] = new[] { "ja", "yes", "sí", "oui" },
        ["No"] = new[] { "nein", "no", "no", "non" },
        ["WirelessAccessPoint"] = new[] { "WLAN-Zugangspunkt", "Wireless access point", "Punto de acceso inalámbrico", "Point d’accès sans fil" },
        ["LanSwitchOf"] = new[] { "LAN-Switch", "LAN switch", "Switch LAN", "Switch LAN" },
        ["MediumWifi"] = new[] { "WLAN (802.11)", "Wi-Fi (802.11)", "Wi-Fi (802.11)", "Wi-Fi (802.11)" },
        ["OtherDevices"] = new[] { "Weitere Geräte (Position im Netzwerk nicht ermittelt)", "Other devices (position in network not determined)", "Otros dispositivos (posición en la red no determinada)", "Autres appareils (position dans le réseau non déterminée)" },

        ["OpenWeb"] = new[] { "Weboberfläche öffnen", "Open web interface", "Abrir interfaz web", "Ouvrir l’interface web" },
        ["ShowShares"] = new[] { "Freigaben anzeigen", "Show shares", "Mostrar recursos compartidos", "Afficher les partages" },
        ["CopyIp"] = new[] { "IP-Adresse kopieren", "Copy IP address", "Copiar dirección IP", "Copier l’adresse IP" },
        ["CopyMac"] = new[] { "MAC-Adresse kopieren", "Copy MAC address", "Copiar dirección MAC", "Copier l’adresse MAC" },
        ["Details"] = new[] { "Details …", "Details …", "Detalles …", "Détails …" },

        ["SettingsTitle"] = new[] { "Einstellungen", "Settings", "Configuración", "Paramètres" },
        ["OpenWrtTargets"] = new[] { "OpenWrt-Geräte für SSH (Schlüssel-Login), z. B. root@192.168.1.1 root@192.168.1.2:", "OpenWrt devices for SSH (key login), e.g. root@192.168.1.1 root@192.168.1.2:", "Dispositivos OpenWrt para SSH (inicio con clave), p. ej. root@192.168.1.1 root@192.168.1.2:", "Appareils OpenWrt pour SSH (connexion par clé), p. ex. root@192.168.1.1 root@192.168.1.2 :" },
        ["OptTopology"] = new[] { "Topologie per LLTD ermitteln (Switches erkennen)", "Determine topology via LLTD (detect switches)", "Determinar la topología mediante LLTD (detectar switches)", "Déterminer la topologie via LLTD (détecter les switchs)" },
        ["OptPlaceOthers"] = new[] { "Geräte ohne LLTD ebenfalls einordnen (dauert länger)", "Also place devices without LLTD (takes longer)", "Ubicar también los dispositivos sin LLTD (tarda más)", "Placer aussi les appareils sans LLTD (plus long)" },
        ["OptNsdp"] = new[] { "Netgear-Switches per NSDP abfragen", "Query Netgear switches via NSDP", "Consultar switches Netgear mediante NSDP", "Interroger les switchs Netgear via NSDP" },
        ["OptMdns"] = new[] { "mDNS/Zeroconf-Dienste abfragen", "Query mDNS/Zeroconf services", "Consultar servicios mDNS/Zeroconf", "Interroger les services mDNS/Zeroconf" },
        ["OptPing"] = new[] { "Vor dem Scan das ganze Subnetz anpingen", "Ping the whole subnet before scanning", "Hacer ping a toda la subred antes del escaneo", "Pinger tout le sous-réseau avant l’analyse" },
        ["OptMaxMinutes"] = new[] { "Höchstdauer der Topologietests (Minuten):", "Maximum duration of topology tests (minutes):", "Duración máxima de las pruebas de topología (minutos):", "Durée maximale des tests de topologie (minutes) :" },
        ["OptLanguage"] = new[] { "Sprache:", "Language:", "Idioma:", "Langue :" },
        ["LanguageSystem"] = new[] { "Wie Windows", "Same as Windows", "Igual que Windows", "Comme Windows" },
        ["OK"] = new[] { "OK", "OK", "Aceptar", "OK" },
        ["LogTitle"] = new[] { "Protokoll des letzten Scans", "Log of the last scan", "Registro del último escaneo", "Journal de la dernière analyse" },
        ["CopyAll"] = new[] { "Alles kopieren", "Copy all", "Copiar todo", "Tout copier" },

        ["DT_Computer"] = new[] { "Computer", "Computer", "Ordenador", "Ordinateur" },
        ["DT_Phone"] = new[] { "Smartphone", "Smartphone", "Smartphone", "Smartphone" },
        ["DT_Tablet"] = new[] { "Tablet", "Tablet", "Tableta", "Tablette" },
        ["DT_Printer"] = new[] { "Drucker", "Printer", "Impresora", "Imprimante" },
        ["DT_Tv"] = new[] { "Fernseher", "TV", "Televisor", "Téléviseur" },
        ["DT_MediaPlayer"] = new[] { "Medienwiedergabe", "Media player", "Reproductor multimedia", "Lecteur multimédia" },
        ["DT_Iot"] = new[] { "IoT-Gerät", "IoT device", "Dispositivo IoT", "Objet connecté" },
        ["DT_Nas"] = new[] { "NAS", "NAS", "NAS", "NAS" },
        ["DT_EchoDot"] = new[] { "Echo Dot", "Echo Dot", "Echo Dot", "Echo Dot" },
        ["DT_EchoSpot"] = new[] { "Echo Spot", "Echo Spot", "Echo Spot", "Echo Spot" },
        ["DT_EchoShow"] = new[] { "Echo Show", "Echo Show", "Echo Show", "Echo Show" },
        ["DT_AmazonDevice"] = new[] { "Amazon-Gerät", "Amazon device", "Dispositivo Amazon", "Appareil Amazon" },
        ["DT_FireTv"] = new[] { "Fire TV", "Fire TV", "Fire TV", "Fire TV" },
        ["DT_GoogleSpeaker"] = new[] { "Google-Lautsprecher", "Google speaker", "Altavoz de Google", "Enceinte Google" },
        ["DT_GoogleDisplay"] = new[] { "Google-Display", "Google display", "Pantalla de Google", "Écran Google" },
        ["DT_Chromecast"] = new[] { "Chromecast", "Chromecast", "Chromecast", "Chromecast" },
        ["DT_GoogleDevice"] = new[] { "Google-Gerät", "Google device", "Dispositivo de Google", "Appareil Google" },
        ["DT_HeatingController"] = new[] { "Heizungsregler", "Heating controller", "Controlador de calefacción", "Régulateur de chauffage" },
        ["DT_Receiver"] = new[] { "Receiver", "Receiver", "Receptor", "Récepteur" },
        ["DT_AirConditioner"] = new[] { "Klimagerät", "Air conditioner", "Aire acondicionado", "Climatiseur" },
        ["Kind_Switch"] = new[] { "Switch", "Switch", "Switch", "Switch" },
        ["Kind_AccessPoint"] = new[] { "Zugangspunkt", "Access point", "Punto de acceso", "Point d’accès" },
        ["Kind_Repeater"] = new[] { "WLAN-Repeater", "Wi-Fi repeater", "Repetidor Wi-Fi", "Répéteur Wi-Fi" },
        ["Kind_Router"] = new[] { "Router", "Router", "Router", "Routeur" },
    };
}
