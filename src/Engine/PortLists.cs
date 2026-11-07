namespace TryZ.Engine;

/// <summary>Port sets used by the TCP sweep, and the default service name of well-known ports.</summary>
internal static class PortLists
{
    // The 100 most frequently open TCP ports from nmap-services, in descending frequency (the set nmap -F scans).
    private static readonly int[] Top100Ordered =
    {
        80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080, 1723, 111, 995, 993, 5900,
        1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001, 10000, 514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554,
        26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646, 5000, 5631, 631, 49153, 8081, 2049, 88, 79, 5800, 106,
        2121, 1110, 49155, 6000, 513, 990, 5357, 427, 49156, 543, 544, 5101, 144, 7, 389, 8009, 3128, 444, 9999, 5009,
        7070, 5190, 3000, 5432, 1900, 3986, 13, 1029, 9, 5051, 6646, 49157, 1028, 873, 1755, 2717, 4899, 9100, 119, 37,
    };

    // The full nmap top-1000 TCP set (identical to the "services" attribute nmap prints for a default -sT/-sS scan).
    private const string Top1000Ranges =
        "1,3-4,6-7,9,13,17,19-26,30,32-33,37,42-43,49,53,70,79-85,88-90,99-100,106,109-111,113,119,125,135,139,143-144,146,161,163,179,199," +
        "211-212,222,254-256,259,264,280,301,306,311,340,366,389,406-407,416-417,425,427,443-445,458,464-465,481,497,500,512-515,524,541," +
        "543-545,548,554-555,563,587,593,616-617,625,631,636,646,648,666-668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787," +
        "800-801,808,843,873,880,888,898,900-903,911-912,981,987,990,992-993,995,999-1002,1007,1009-1011,1021-1100,1102,1104-1108,1110-1114," +
        "1117,1119,1121-1124,1126,1130-1132,1137-1138,1141,1145,1147-1149,1151-1152,1154,1163-1166,1169,1174-1175,1183,1185-1187,1192," +
        "1198-1199,1201,1213,1216-1218,1233-1234,1236,1244,1247-1248,1259,1271-1272,1277,1287,1296,1300-1301,1309-1311,1322,1328,1334,1352," +
        "1417,1433-1434,1443,1455,1461,1494,1500-1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687-1688,1700,1717-1721," +
        "1723,1755,1761,1782-1783,1801,1805,1812,1839-1840,1862-1864,1875,1900,1914,1935,1947,1971-1972,1974,1984,1998-2010,2013,2020-2022," +
        "2030,2033-2035,2038,2040-2043,2045-2049,2065,2068,2099-2100,2103,2105-2107,2111,2119,2121,2126,2135,2144,2160-2161,2170,2179," +
        "2190-2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381-2383,2393-2394,2399,2401,2492,2500,2522,2525,2557,2601-2602,2604-2605," +
        "2607-2608,2638,2701-2702,2710,2717-2718,2725,2800,2809,2811,2869,2875,2909-2910,2920,2967-2968,2998,3000-3001,3003,3005-3007,3011," +
        "3013,3017,3030-3031,3052,3071,3077,3128,3168,3211,3221,3260-3261,3268-3269,3283,3300-3301,3306,3322-3325,3333,3351,3367,3369-3372," +
        "3389-3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689-3690,3703,3737,3766,3784,3800-3801,3809,3814,3826-3828,3851,3869,3871," +
        "3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000-4006,4045,4111,4125-4126,4129,4224,4242,4279,4321,4343,4443-4446," +
        "4449,4550,4567,4662,4848,4899-4900,4998,5000-5004,5009,5030,5033,5050-5051,5054,5060-5061,5080,5087,5100-5102,5120,5190,5200,5214," +
        "5221-5222,5225-5226,5269,5280,5298,5357,5405,5414,5431-5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678-5679,5718," +
        "5730,5800-5802,5810-5811,5815,5822,5825,5850,5859,5862,5877,5900-5904,5906-5907,5910-5911,5915,5922,5925,5950,5952,5959-5963," +
        "5987-5989,5998-6007,6009,6025,6059,6100-6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,6547,6565-6567,6580,6646,6666-6669," +
        "6689,6692,6699,6779,6788-6789,6792,6839,6881,6901,6969,7000-7002,7004,7007,7019,7025,7070,7100,7103,7106,7200-7201,7402,7435,7443," +
        "7496,7512,7625,7627,7676,7741,7777-7778,7800,7911,7920-7921,7937-7938,7999-8002,8007-8011,8021-8022,8031,8042,8045,8080-8090,8093," +
        "8099-8100,8180-8181,8192-8194,8200,8222,8254,8290-8292,8300,8333,8383,8400,8402,8443,8500,8600,8649,8651-8652,8654,8701,8800,8873," +
        "8888,8899,8994,9000-9003,9009-9011,9040,9050,9071,9080-9081,9090-9091,9099-9103,9110-9111,9200,9207,9220,9290,9415,9418,9485,9500," +
        "9502-9503,9535,9575,9593-9595,9618,9666,9876-9878,9898,9900,9917,9929,9943-9944,9968,9998-10004,10009-10010,10012,10024-10025," +
        "10082,10180,10215,10243,10566,10616-10617,10621,10626,10628-10629,10778,11110-11111,11967,12000,12174,12265,12345,13456,13722," +
        "13782-13783,14000,14238,14441-14442,15000,15002-15004,15660,15742,16000-16001,16012,16016,16018,16080,16113,16992-16993,17877," +
        "17988,18040,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221-20222,20828,21571,22939,23502,24444," +
        "24800,25734-25735,26214,27000,27352-27353,27355-27356,27715,28201,30000,30718,30951,31038,31337,32768-32785,33354,33899," +
        "34571-34573,35500,38292,40193,40911,41511,42510,44176,44442-44443,44501,45100,48080,49152-49161,49163,49165,49167,49175-49176," +
        "49400,49999-50003,50006,50300,50389,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,55055-55056,55555,55600," +
        "56737-56738,57294,57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,65129,65389";

    private static readonly int[] WebPorts =
    {
        80, 81, 443, 591, 2082, 2083, 2086, 2087, 3000, 4443, 5000, 5001, 7001, 7443, 8000, 8008,
        8080, 8081, 8088, 8443, 8888, 9000, 9090, 9443,
    };

    private static readonly Lazy<int[]> _top1000 = new(BuildTop1000);
    private static readonly Lazy<int[]> _all = new(() => Enumerable.Range(1, 65535).ToArray());

    /// <summary>nmap's 100 most common TCP ports, most frequent first.</summary>
    public static IReadOnlyList<int> Top100 => Top100Ordered;

    /// <summary>nmap's 1000 most common TCP ports: the top 100 by frequency first, then the rest ascending.</summary>
    public static IReadOnlyList<int> Top1000 => _top1000.Value;

    public static IReadOnlyList<int> Web => WebPorts;

    public static IReadOnlyList<int> All => _all.Value;

    public static IReadOnlyList<int> For(ScanOptions options) => options.Ports switch
    {
        PortSelection.Top100 => Top100,
        PortSelection.All => All,
        PortSelection.Web => Web,
        _ => Top1000,
    };

    private static int[] BuildTop1000()
    {
        var set = new SortedSet<int>();
        foreach (var part in Top1000Ranges.Split(','))
        {
            int dash = part.IndexOf('-');
            if (dash < 0)
            {
                set.Add(int.Parse(part, System.Globalization.CultureInfo.InvariantCulture));
                continue;
            }
            int a = int.Parse(part.AsSpan(0, dash), System.Globalization.CultureInfo.InvariantCulture);
            int b = int.Parse(part.AsSpan(dash + 1), System.Globalization.CultureInfo.InvariantCulture);
            for (int p = a; p <= b; p++) set.Add(p);
        }
        var result = new List<int>(set.Count);
        var seen = new HashSet<int>();
        foreach (int p in Top100Ordered)
            if (set.Contains(p) && seen.Add(p)) result.Add(p);
        foreach (int p in set)
            if (seen.Add(p)) result.Add(p);
        return result.ToArray();
    }

    /// <summary>IANA-style default service name for a port, or "unknown".</summary>
    public static string GuessService(int port) => Services.TryGetValue(port, out var name) ? name : "unknown";

    private static readonly Dictionary<int, string> Services = new()
    {
        [1] = "tcpmux", [7] = "echo", [9] = "discard", [11] = "systat", [13] = "daytime", [15] = "netstat", [17] = "qotd",
        [19] = "chargen", [20] = "ftp-data", [21] = "ftp", [22] = "ssh", [23] = "telnet", [25] = "smtp", [26] = "rsftp",
        [37] = "time", [42] = "nameserver", [43] = "whois", [49] = "tacacs", [53] = "domain", [67] = "dhcps", [69] = "tftp",
        [70] = "gopher", [79] = "finger", [80] = "http", [81] = "http", [82] = "xfer", [83] = "mit-ml-dev", [84] = "ctf",
        [85] = "mit-ml-dev", [88] = "kerberos-sec", [89] = "su-mit-tg", [90] = "dnsix", [99] = "metagram", [100] = "newacct",
        [102] = "iso-tsap", [106] = "pop3pw", [109] = "pop2", [110] = "pop3", [111] = "rpcbind", [113] = "ident", [119] = "nntp",
        [123] = "ntp", [135] = "msrpc", [137] = "netbios-ns", [138] = "netbios-dgm", [139] = "netbios-ssn", [143] = "imap",
        [144] = "news", [161] = "snmp", [162] = "snmptrap", [163] = "cmip-man", [179] = "bgp", [194] = "irc", [199] = "smux",
        [211] = "914c-g", [212] = "anet", [222] = "rsh-spx", [264] = "bgmp", [280] = "http-mgmt", [301] = "unknown",
        [311] = "asip-webadmin", [389] = "ldap", [406] = "imsp", [407] = "timbuktu", [427] = "svrloc", [443] = "https",
        [444] = "snpp", [445] = "microsoft-ds", [464] = "kpasswd5", [465] = "smtps", [497] = "retrospect", [500] = "isakmp",
        [502] = "modbus", [512] = "exec", [513] = "login", [514] = "shell", [515] = "printer", [520] = "efs", [524] = "ncp",
        [541] = "uucp-rlogin", [543] = "klogin", [544] = "kshell", [545] = "ekshell", [548] = "afp", [554] = "rtsp",
        [555] = "dsf", [563] = "snews", [587] = "submission", [591] = "http-alt", [593] = "http-rpc-epmap", [623] = "oob-ws-http",
        [625] = "apple-xsrvr-admin", [631] = "ipp", [636] = "ldaps", [646] = "ldp", [666] = "doom", [691] = "resvc",
        [700] = "epp", [749] = "kerberos-adm", [750] = "kerberos", [765] = "webster", [777] = "multiling-http", [808] = "ccproxy-http",
        [843] = "unknown", [873] = "rsync", [902] = "iss-realsecure", [903] = "iss-console-mgr", [989] = "ftps-data", [990] = "ftps",
        [992] = "telnets", [993] = "imaps", [994] = "ircs", [995] = "pop3s", [1025] = "NFS-or-IIS", [1026] = "LSA-or-nterm",
        [1027] = "IIS", [1028] = "unknown", [1029] = "ms-lsa", [1080] = "socks", [1099] = "rmiregistry", [1110] = "nfsd-status",
        [1194] = "openvpn", [1214] = "fasttrack", [1241] = "nessus", [1311] = "rxmon", [1352] = "lotusnotes", [1433] = "ms-sql-s",
        [1434] = "ms-sql-m", [1494] = "citrix-ica", [1521] = "oracle", [1524] = "ingreslock", [1583] = "pervasive-sql",
        [1604] = "citrix-icabrowser", [1645] = "radius", [1701] = "l2tp", [1720] = "h323q931", [1723] = "pptp", [1755] = "wms",
        [1812] = "radius", [1813] = "radacct", [1883] = "mqtt", [1900] = "upnp", [1935] = "rtmp", [1984] = "bigbrother",
        [2000] = "cisco-sccp", [2001] = "dc", [2049] = "nfs", [2082] = "infowave", [2083] = "radsec", [2086] = "gnunet",
        [2087] = "eli", [2100] = "amiganetfs", [2121] = "ccproxy-ftp", [2181] = "zookeeper", [2222] = "EtherNetIP-1",
        [2375] = "docker", [2376] = "docker-s", [2379] = "etcd-client", [2380] = "etcd-server", [2381] = "compaq-https",
        [2401] = "cvspserver", [2483] = "oracle-tcps", [2484] = "oracle-tcps", [2525] = "ms-v-worlds", [2601] = "zebra",
        [2604] = "ospfd", [2638] = "sybase", [2717] = "pn-requester", [2869] = "icslap", [3000] = "ppp", [3050] = "gds_db",
        [3128] = "squid-http", [3268] = "globalcatLDAP", [3269] = "globalcatLDAPssl", [3283] = "netassistant",
        [3306] = "mysql", [3389] = "ms-wbt-server", [3478] = "stun", [3632] = "distccd", [3689] = "rendezvous",
        [3690] = "svn", [3986] = "mapper-ws_ethd", [4000] = "remoteanything", [4369] = "epmd", [4443] = "pharos",
        [4444] = "krb524", [4505] = "salt-pub", [4506] = "salt-ret", [4567] = "tram", [4848] = "appserv-http",
        [4899] = "radmin", [5000] = "upnp", [5001] = "commplex-link", [5009] = "airport-admin", [5038] = "asterisk",
        [5051] = "ida-agent", [5060] = "sip", [5061] = "sip-tls", [5101] = "admdog", [5190] = "aol", [5222] = "xmpp-client",
        [5269] = "xmpp-server", [5357] = "wsdapi", [5353] = "mdns", [5432] = "postgresql", [5555] = "freeciv",
        [5601] = "kibana", [5631] = "pcanywheredata", [5666] = "nrpe", [5672] = "amqp", [5800] = "vnc-http",
        [5801] = "vnc-http-1", [5900] = "vnc", [5901] = "vnc-1", [5902] = "vnc-2", [5903] = "vnc-3", [5984] = "couchdb",
        [5985] = "wsman", [5986] = "wsmans", [6000] = "X11", [6001] = "X11:1", [6379] = "redis", [6443] = "kubernetes-api",
        [6646] = "unknown", [6660] = "irc", [6666] = "irc", [6667] = "irc", [6697] = "ircs-u", [7001] = "afs3-callback",
        [7070] = "realserver", [7443] = "oracleas-https", [7474] = "neo4j", [7547] = "cwmp", [7777] = "cbt", [8000] = "http-alt",
        [8008] = "http", [8009] = "ajp13", [8080] = "http-proxy", [8081] = "blackice-icecap", [8086] = "influxdb",
        [8088] = "radan-http", [8089] = "splunkd", [8443] = "https-alt", [8500] = "fmtp", [8834] = "nessus-xmlrpc",
        [8880] = "cddbp-alt", [8883] = "secure-mqtt", [8888] = "sun-answerbook", [9000] = "cslistener", [9001] = "tor-orport",
        [9042] = "cassandra", [9090] = "zeus-admin", [9092] = "kafka", [9100] = "jetdirect", [9200] = "elasticsearch",
        [9300] = "vrace", [9418] = "git", [9443] = "tungsten-https", [9999] = "abyss", [10000] = "snet-sensor-mgmt",
        [10250] = "kubelet", [11211] = "memcache", [15672] = "rabbitmq-mgmt", [27017] = "mongod", [27018] = "mongod",
        [28017] = "mongod-http", [32768] = "filenet-tms", [49152] = "unknown", [50000] = "ibm-db2", [50070] = "hadoop-namenode",
    };
}
