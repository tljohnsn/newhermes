#!/usr/bin/perl                                                                                                                           
use strict;
use Getopt::Long;
use Cwd;
use POSIX ":sys_wait_h";
use Time::HiRes qw(sleep);
use 5.010;

my $SERVER="https://127.0.0.1:8834";
my $POLICY=`date +auto-%F-%k%M`; chomp($POLICY);
my $accesskey="";
my $secretkey="";
my $targetsfile = "targets.txt";
my $skipnmap;
my $nmapfile = "client.log";
my $nessususer = "";
my $nessuspass = "";
my $mailfrom;
my $mailto;
my $client = "PCI";
my $outputfile = $POLICY . ".nessus";
my $mainframe;
my $starthour;
my $stophour;
my $smtpserver = "smtp.example.com";

GetOptions ("targetsfile=s" => \$targetsfile,
	    "nmapfile=s" => \$nmapfile,
	    "client=s" => \$client,
	    "user|u=s" => \$nessususer,
	    "pass|p=s" => \$nessuspass,
	    "accesskey|a=s" => \$accesskey,
	    "secretkey|k=s" => \$secretkey,
	    "sender|s=s" => \$mailfrom,
	    "to|t=s" => \$mailto,
	    "outputfile=s" => \$outputfile,
	    "nessus|n=s" => \$SERVER,
	    "mainframe" => \$mainframe,
	    "starthour=s" => \$starthour,
	    "stophour=s" => \$stophour,
	    "skipnmap" => \$skipnmap);

print ("\n\n$targetsfile , $nmapfile, $nessususer, $nessuspass, $SERVER\n\n");
#The old way with login / password
#my $nessusHeader = "X-Cookie: token=$TOKEN";
#The new way with api keys
my $nessusHeader = "X-ApiKeys: accessKey=$accesskey; secretKey=$secretkey";


my @pluginids = (18405,57608,58453,57690);
my $ports = "3389,139";
my $targets = "127.0.0.1";

my $nmap;
if ($mainframe) {
    #this nmap command is for mainframe and tandem boxes that can fall over easily
    $nmap = "nmap -Pn -sV -sC -sT -sU -T4 -p T:1-65535,U:2-3,7,9,13,17,19-23,37-38,42,49,53,67-69,80,88,111-113,120,123,135-139,158,161-162,177,192,199,207,217,363,389,402,407,427,434,443,445,464,497,500,502,512-515,517-518,520,539,559,593,623,626,631,639,643,657,664,682-689,764,767,772-776,780-782,786,789,800,814,826,829,838,902-903,944,959,965,983,989-990,996-1001,1007-1008,1012-1014,1019-1051,1053-1060,1064-1070,1072,1080-1081,1087-1088,1090,1100-1101,1105,1124,1200,1214,1234,1346,1419,1433-1434,1455,1457,1484-1485,1524,1645-1646,1701,1718-1719,1761,1782,1804,1812-1813,1885-1886,1900-1901,1993,2000,2002,2048-2049,2051,2148,2160-2161,2222-2223,2343,2345,2362,2967,3052,3130,3283,3296,3343,3389,3401,3456-3457,3659,3664,3702-3703,4000,4008,4045,4444,4500,4666,4672,5000-5003,5010,5050,5060,5093,5351,5353,5355,5500,5555,5632,6000-6002,6004,6050,6346-6347,6970-6971,7000,7938,8000-8001,8010,8181,8193,8900,9000-9001,9020,9103,9199-9200,9370,9876-9877,9950,10000,10080,11487,16086,16402,16420,16430,16433,16449,16498,16503,16545,16548,16573,16674,16680,16697,16700,16708,16711,16739,16766,16779,16786,16816,16829,16832,16838-16839,16862,16896,16912,16918-16919,16938-16939,16947-16948,16970,16972,16974,17006,17018,17077,17091,17101,17146,17184-17185,17205,17207,17219,17236-17237,17282,17302,17321,17331-17332,17338,17359,17417,17423-17424,17455,17459,17468,17487,17490,17494,17505,17533,17549,17573,17580,17585,17592,17605,17615-17616,17629,17638,17663,17673-17674,17683,17726,17754,17762,17787,17814,17823-17824,17836,17845,17888,17939,17946,17989,18004,18081,18113,18134,18156,18228,18234,18250,18255,18258,18319,18331,18360,18373,18449,18485,18543,18582,18605,18617,18666,18669,18676,18683,18807,18818,18821,18830,18832,18835,18869,18883,18888,18958,18980,18985,18987,18991,18994,18996,19017,19022,19039,19047,19075,19096,19120,19130,19140-19141,19154,19161,19165,19181,19193,19197,19222,19227,19273,19283,19294,19315,19322,19332,19374,19415,19482,19489,19500,19503-19504,19541,19600,19605,19616,19624-19625,19632,19639,19647,19650,19660,19662-19663,19682-19683,19687,19695,19707,19717-19719,19722,19728,19789,19792,19933,19935-19936,19956,19995,19998,20003-20004,20019,20031,20082,20117,20120,20126,20129,20146,20154,20164,20206,20217,20249,20262,20279,20288,20309,20313,20326,20359-20360,20366,20380,20389,20409,20411,20423-20425,20445,20449,20464-20465,20518,20522,20525,20540,20560,20665,20678-20679,20710,20717,20742,20752,20762,20791,20817,20842,20848,20851,20865,20872,20876,20884,20919,21000,21016,21060,21083,21104,21111,21131,21167,21186,21206-21207,21212,21247,21261,21282,21298,21303,21318,21320,21333,21344,21354,21358,21360,21364,21366,21383,21405,21454,21468,21476,21514,21524-21525,21556,21566,21568,21576,21609,21621,21625,21644,21649,21655,21663,21674,21698,21702,21710,21742,21780,21784,21800,21803,21834,21842,21847,21868,21898,21902,21923,21948,21967,22029,22043,22045,22053,22055,22105,22109,22123-22124,22341,22692,22695,22739,22799,22846,22914,22986,22996,23040,23176,23354,23531,23557,23608,23679,23781,23965,23980,24007,24279,24511,24594,24606,24644,24854,24910,25003,25157,25240,25280,25337,25375,25462,25541,25546,25709,25931,26407,26415,26720,26872,26966,27015,27195,27444,27473,27482,27707,27892,27899,28122,28369,28465,28493,28543,28547,28641,28840,28973,29078,29243,29256,29810,29823,29977,30263,30303,30365,30544,30656,30697,30704,30718,30975,31059,31073,31109,31189,31195,31335,31337,31365,31625,31681,31731,31891,32345,32385,32528,32768-32780,32798,32815,32818,32931,33030,33249,33281,33354-33355,33459,33717,33744,33866,33872,34038,34079,34125,34358,34422,34433,34555,34570,34577-34580,34758,34796,34855,34861-34862,34892,35438,35702,35777,35794,36108,36206,36384,36458,36489,36669,36778,36893,36945,37144,37212,37393,37444,37602,37761,37783,37813,37843,38037,38063,38293,38412,38498,38615,39213,39217,39632,39683,39714,39723,39888,40019,40116,40441,40539,40622,40708,40711,40724,40732,40805,40847,40866,40915,41058,41081,41308,41370,41446,41524,41638,41702,41774,41896,41967,41971,42056,42172,42313,42431,42434,42508,42557,42577,42627,42639,43094,43195,43370,43514,43686,43824,43967,44101,44160,44179,44185,44190,44253,44334,44508,44923,44946,44968,45247,45380,45441,45685,45722,45818,45928,46093,46532,46836,47624,47765,47772,47808,47915,47981,48078,48189,48255,48455,48489,48761,49152-49163,49165-49182,49184-49202,49204-49205,49207-49216,49220,49222,49226,49259,49262,49306,49350,49360,49393,49396,49503,49640,49968,50099,50164,50497,50612,50708,50919,51255,51456,51554,51586,51690,51717,51905,51972,52144,52225,52503,53006,53037,53571,53589,53838,54094,54114,54281,54321,54711,54807,54925,55043,55544,55587,56141,57172,57409-57410,57813,57843,57958,57977,58002,58075,58178,58419,58631,58640,58797,59193,59207,59765,59846,60172,60381,60423,61024,61142,61319,61322,61370,61412,61481,61550,61685,61961,62154,62287,62575,62677,62699,62958,63420,63555,64080,64481,64513,64590,64727,65024 -Pn -oA $nmapfile --webxml -iL $targetsfile -vvv";
} else {
    $nmap = "nmap -Pn -sV -sC -sS -sU -T4 -p T:1-65535,U:2-3,7,9,13,17,19-23,37-38,42,49,53,67-69,80,88,111-113,120,123,135-139,158,161-162,177,192,199,207,217,363,389,402,407,427,434,443,445,464,497,500,502,512-515,517-518,520,539,559,593,623,626,631,639,643,657,664,682-689,764,767,772-776,780-782,786,789,800,814,826,829,838,902-903,944,959,965,983,989-990,996-1001,1007-1008,1012-1014,1019-1051,1053-1060,1064-1070,1072,1080-1081,1087-1088,1090,1100-1101,1105,1124,1200,1214,1234,1346,1419,1433-1434,1455,1457,1484-1485,1524,1645-1646,1701,1718-1719,1761,1782,1804,1812-1813,1885-1886,1900-1901,1993,2000,2002,2048-2049,2051,2148,2160-2161,2222-2223,2343,2345,2362,2967,3052,3130,3283,3296,3343,3389,3401,3456-3457,3659,3664,3702-3703,4000,4008,4045,4444,4500,4666,4672,5000-5003,5010,5050,5060,5093,5351,5353,5355,5500,5555,5632,6000-6002,6004,6050,6346-6347,6970-6971,7000,7938,8000-8001,8010,8181,8193,8900,9000-9001,9020,9103,9199-9200,9370,9876-9877,9950,10000,10080,11487,16086,16402,16420,16430,16433,16449,16498,16503,16545,16548,16573,16674,16680,16697,16700,16708,16711,16739,16766,16779,16786,16816,16829,16832,16838-16839,16862,16896,16912,16918-16919,16938-16939,16947-16948,16970,16972,16974,17006,17018,17077,17091,17101,17146,17184-17185,17205,17207,17219,17236-17237,17282,17302,17321,17331-17332,17338,17359,17417,17423-17424,17455,17459,17468,17487,17490,17494,17505,17533,17549,17573,17580,17585,17592,17605,17615-17616,17629,17638,17663,17673-17674,17683,17726,17754,17762,17787,17814,17823-17824,17836,17845,17888,17939,17946,17989,18004,18081,18113,18134,18156,18228,18234,18250,18255,18258,18319,18331,18360,18373,18449,18485,18543,18582,18605,18617,18666,18669,18676,18683,18807,18818,18821,18830,18832,18835,18869,18883,18888,18958,18980,18985,18987,18991,18994,18996,19017,19022,19039,19047,19075,19096,19120,19130,19140-19141,19154,19161,19165,19181,19193,19197,19222,19227,19273,19283,19294,19315,19322,19332,19374,19415,19482,19489,19500,19503-19504,19541,19600,19605,19616,19624-19625,19632,19639,19647,19650,19660,19662-19663,19682-19683,19687,19695,19707,19717-19719,19722,19728,19789,19792,19933,19935-19936,19956,19995,19998,20003-20004,20019,20031,20082,20117,20120,20126,20129,20146,20154,20164,20206,20217,20249,20262,20279,20288,20309,20313,20326,20359-20360,20366,20380,20389,20409,20411,20423-20425,20445,20449,20464-20465,20518,20522,20525,20540,20560,20665,20678-20679,20710,20717,20742,20752,20762,20791,20817,20842,20848,20851,20865,20872,20876,20884,20919,21000,21016,21060,21083,21104,21111,21131,21167,21186,21206-21207,21212,21247,21261,21282,21298,21303,21318,21320,21333,21344,21354,21358,21360,21364,21366,21383,21405,21454,21468,21476,21514,21524-21525,21556,21566,21568,21576,21609,21621,21625,21644,21649,21655,21663,21674,21698,21702,21710,21742,21780,21784,21800,21803,21834,21842,21847,21868,21898,21902,21923,21948,21967,22029,22043,22045,22053,22055,22105,22109,22123-22124,22341,22692,22695,22739,22799,22846,22914,22986,22996,23040,23176,23354,23531,23557,23608,23679,23781,23965,23980,24007,24279,24511,24594,24606,24644,24854,24910,25003,25157,25240,25280,25337,25375,25462,25541,25546,25709,25931,26407,26415,26720,26872,26966,27015,27195,27444,27473,27482,27707,27892,27899,28122,28369,28465,28493,28543,28547,28641,28840,28973,29078,29243,29256,29810,29823,29977,30263,30303,30365,30544,30656,30697,30704,30718,30975,31059,31073,31109,31189,31195,31335,31337,31365,31625,31681,31731,31891,32345,32385,32528,32768-32780,32798,32815,32818,32931,33030,33249,33281,33354-33355,33459,33717,33744,33866,33872,34038,34079,34125,34358,34422,34433,34555,34570,34577-34580,34758,34796,34855,34861-34862,34892,35438,35702,35777,35794,36108,36206,36384,36458,36489,36669,36778,36893,36945,37144,37212,37393,37444,37602,37761,37783,37813,37843,38037,38063,38293,38412,38498,38615,39213,39217,39632,39683,39714,39723,39888,40019,40116,40441,40539,40622,40708,40711,40724,40732,40805,40847,40866,40915,41058,41081,41308,41370,41446,41524,41638,41702,41774,41896,41967,41971,42056,42172,42313,42431,42434,42508,42557,42577,42627,42639,43094,43195,43370,43514,43686,43824,43967,44101,44160,44179,44185,44190,44253,44334,44508,44923,44946,44968,45247,45380,45441,45685,45722,45818,45928,46093,46532,46836,47624,47765,47772,47808,47915,47981,48078,48189,48255,48455,48489,48761,49152-49163,49165-49182,49184-49202,49204-49205,49207-49216,49220,49222,49226,49259,49262,49306,49350,49360,49393,49396,49503,49640,49968,50099,50164,50497,50612,50708,50919,51255,51456,51554,51586,51690,51717,51905,51972,52144,52225,52503,53006,53037,53571,53589,53838,54094,54114,54281,54321,54711,54807,54925,55043,55544,55587,56141,57172,57409-57410,57813,57843,57958,57977,58002,58075,58178,58419,58631,58640,58797,59193,59207,59765,59846,60172,60381,60423,61024,61142,61319,61322,61370,61412,61481,61550,61685,61961,62154,62287,62575,62677,62699,62958,63420,63555,64080,64481,64513,64590,64727,65024 -Pn -oA $nmapfile --webxml -iL $targetsfile -vvv";
}

if($skipnmap) { say "skipping nmap" }else {

#fork the nmap process so we can start / stop it as per business needs
my $pid = fork();
die "Could not fork\n" if not defined $pid;

if (not $pid) {
    say "In child - execing nmap";
    exec("$nmap");
}

say "In parent of $pid";
while (1) {
    my $res = waitpid($pid, WNOHANG);
    my $hour = (localtime)[2];
    if ($hour >= $stophour and $hour < $starthour) {
	system("kill -SIGTSTP $pid");
	say("stopping nmap");
    }else {
	system("kill -SIGCONT $pid");
	say("resuming nmap");
    }
    say "Res: $res nmap pid is:$pid hour is:$hour start is:$starthour stop is:$stophour";
    sleep(10);
    
    if ($res == -1) {
	say "Some error occurred ", $? >> 8;
	exit();
    }
    if ($res) {
	say "Child $res ended with ", $? >> 8;
	last;
    }
}

say "about to wait()";
say wait();
say "wait() done";
    }

#if ($mainframe) {
#    print "Sleeping...\n";
#    sleep(900);
#}

# Login to the server to get a token
my $cmd="curl -k -s -X POST -H \'Content-Type: application/json\' -d \'{\"username\":\"$nessususer\",\"password\":\"$nessuspass\"}\' $SERVER/session | cut -d \\\" -f 4";
#my $TOKEN=`$cmd`;
#chomp($TOKEN);
my $TOKEN="";
my $curl="curl -s -k";

my %enablefams = ();
foreach my $plugin (@pluginids) {
    $cmd="curl -s -k -X GET -H \"$nessusHeader\" $SERVER/plugins/plugin/$plugin | jq .family_name";
    my $fam = `$cmd`; chomp($fam);
    push(@{$enablefams{$fam}}, $plugin);
#    print $fam;
}


$cmd = "$curl -X 'POST' -H \"$nessusHeader\" -F 'Filename=out.xml' -F 'Filedata=\@$nmapfile.xml' $SERVER/file/upload";
print $cmd;
my $uploadresult = `$cmd | jq .fileuploaded`;
chomp($uploadresult);
$uploadresult =~ s/"//g;
print $uploadresult;


my $data = '{
  "uuid": "e460ea7c-7916-d001-51dc-e43ef3168e6e20f1d97bdebf4a49",
  "settings": {
    "name": "'. "$client-" . $POLICY .'",
    "description": "",
    "acls": [
      {
        "permissions": "0",
        "type": "default"
      }
    ],
    "discovery_mode": "Custom",
    "ping_the_remote_host": "no",
    "tcp_ping_dest_ports": "built-in",
    "icmp_unreach_means_host_down": "no",
    "icmp_ping_retries": "2",
    "scan_network_printers": "no",
    "scan_netware_hosts": "no",
    "wol_mac_addresses": "",
    "wol_wait_time": "5",
    "network_type": "Mixed (use RFC 1918)",
    "unscanned_closed": "no",
    "portscan_range": "default",
    "ssh_netstat_scanner": "yes",
    "wmi_netstat_scanner": "yes",
    "snmp_scanner": "yes",
    "only_portscan_if_enum_failed": "yes",
    "verify_open_ports": "no",
    "import_nmap_xml": "yes",
    "import_nmap_xml_file": "' . $uploadresult .'",
    "tcp_scanner": "no",
    "syn_scanner": "no",
    "udp_scanner": "no",
    "svc_detection_on_all_ports": "yes",
    "detect_ssl": "yes",
    "ssl_prob_ports": "All ports",
    "cert_expiry_warning_days": "60",
    "enumerate_all_ciphers": "yes",
    "check_crl": "no",
    "assessment_mode": "Custom",
    "report_paranoia": "Normal",
    "thorough_tests": "yes",
    "provided_creds_only": "no",
    "test_default_oracle_accounts": "no",
    "scan_webapps": "no",
    "request_windows_domain_info": "yes",
    "enum_domain_users_start_uid": "1000",
    "enum_domain_users_end_uid": "1200",
    "enum_local_users_start_uid": "1000",
    "enum_local_users_end_uid": "1200",
    "report_verbosity": "Normal",
    "report_superseded_patches": "yes",
    "silent_dependencies": "yes",
    "allow_post_scan_editing": "yes",
    "reverse_lookup": "yes",
    "log_live_hosts": "no",
    "display_unreachable_hosts": "no",
    "advanced_mode": "Default",
    "safe_checks": "yes",
    "stop_scan_on_disconnect": "no",
    "slice_network_addresses": "no",
    "reduce_connections_on_congestion": "yes",
    "use_kernel_congestion_detection": "yes",
    "network_receive_timeout": "15",
    "max_checks_per_host": "4",
    "max_hosts_per_scan": "20",
    "max_simult_tcp_sessions_per_host": "unlimited",
    "max_simult_tcp_sessions_per_scan": "unlimited",
    "log_whole_attack": "no",
    "enable_plugin_debugging": "no",
    "ssh_known_hosts": "",
    "ssh_port": "22",
    "ssh_client_banner": "OpenSSH_5.0",
    "never_send_win_creds_in_the_clear": "yes",
    "dont_use_ntlmv1": "yes",
    "start_remote_registry": "no",
    "enable_admin_shares": "no"
  },
  "credentials": {}
}
';

#print "\n\n$data\n\n";


$cmd="$curl -X 'POST' -H 'Content-Type: application/json; charset=UTF-8' -H \"$nessusHeader\" -H 'X-Requested-With: XMLHttpRequest' -d '$data' $SERVER/policies";
my $policyid = `$cmd | jq .policy_id`;  chomp($policyid);
print $policyid;


$targets = "";
my $filename = $targetsfile;
open(my $fh, '<:encoding(UTF-8)', $filename)
    or die "Could not open file '$filename' $!";
 
while (my $row = <$fh>) {
    chomp $row;
    print "$row\n";
    $targets .= "$row,";
}

#lookup the custom scan template uuid
$cmd = "$curl -H '$nessusHeader' $SERVER/editor/scan/templates | jq '.templates[] | select(.name==\"custom\") | .uuid'";
my $scanuuid = `$cmd`; chomp($scanuuid);
my $scansettings = '{
  "uuid": ' . $scanuuid . ',
  "settings": {
    "filters": [],
    "filter_type": "",
    "emails": "",
    "launch_now": true,
    "enabled": false,
    "name": "' .  "$client-" . $POLICY .'",
    "description": "",
    "folder_id": "10",
    "scanner_id": "1",
    "policy_id": "' . $policyid . '",
    "text_targets": "' . $targets . '",
    "file_targets": "",
    "launch": "ONETIME"
  }';

# Launch the scan and retrieve it's id
#print $scansettings;
$cmd="$curl -X 'POST' -H 'Content-Type: application/json; charset=UTF-8' -H \"$nessusHeader\" -H 'X-Requested-With: XMLHttpRequest' -d '$scansettings' $SERVER/scans";
my $scanid = `$cmd | jq '.scan | .id '`;
chomp ($scanid);
$scanid =~ s/"//;
print $scanid;

my $scanstatus = '"running"';
# Loop until the scan is complete
until ($scanstatus =~ /completed/) {
    print ($scanstatus =~ /completed/);
    $cmd = "$curl -X 'GET' -H 'Content-Type: application/json' -H \"$nessusHeader\" -H 'X-Requested-With: XMLHttpRequest' $SERVER/scans/$scanid";
    $scanstatus = `$cmd | jq '.info | .status'`;
    print "$scanstatus";
    if ($scanstatus !=~ /running/) {
	# Login to the server to get a token
	$cmd="curl -k -s -X POST -H \'Content-Type: application/json\' -d \'{\"username\":\"$nessususer\",\"password\":\"$nessuspass\"}\' $SERVER/session | cut -d \\\" -f 4";
	$TOKEN=`$cmd`;
	chomp($TOKEN);
    }
    #pause per business need
    my $hour = (localtime)[2];
    if ($hour >= $stophour and $hour < $starthour) {

	say "stop nessus scan  hour is:$hour start is:$starthour stop is:$stophour";
	$cmd = "$curl -X 'POST' -H 'Content-Type: application/json' -H \"$nessusHeader\" -H 'X-Requested-With: XMLHttpRequest' $SERVER/scans/$scanid/pause";
	my $junk = `$cmd`;
	print $junk;
    }else{
	say "resume nessus scan hour is:$hour start is:$starthour stop is:$stophour";
	$cmd = "$curl -X 'POST' -H 'Content-Type: application/json' -H \"$nessusHeader\" -H 'X-Requested-With: XMLHttpRequest' $SERVER/scans/$scanid/resume";
	my $junk = `$cmd`;
	print $junk;
    }
    # Did this hack before I realized the scanid was quoted with a newline.  Fixed by adding the chomp and regex above.
    #$cmd = "echo '$scanstatusjs' | jq '.info | .status'";
    #$scanstatus = `$cmd`;
    sleep(1);
}

print "Scan complete\n";

my $exportsettings = '
{
"format": "nessus"
}
';

# Export thescan
$cmd = "$curl -X 'POST' -H 'Content-Type: application/json; charset=UTF-8' -H \"$nessusHeader\" -H 'X-Requested-With: XMLHttpRequest' -d '$exportsettings' $SERVER/scans/$scanid/export";
my $scandl = `$cmd | jq .file`;
chomp($scandl);
print $scandl;

my $expstatus = "no";

# Loop until the export is complete
until ($expstatus =~ /ready/) {
print "loop\n";
$cmd = "$curl -X 'GET' -H 'Content-Type: application/json; charset=UTF-8' -H \"$nessusHeader\" -H 'X-Requested-With: XMLHttpRequest' $SERVER/scans/$scanid/export/$scandl/status";
$expstatus = `$cmd`;
print "$cmd\n";
print $expstatus;
sleep(1);
}

#Download the scan results
$cmd = "$curl -X 'GET' -H 'Content-Type: application/json; charset=UTF-8' -H \"$nessusHeader\" -H 'X-Requested-With: XMLHttpRequest' $SERVER/scans/$scanid/export/$scandl/download";
my $dlfile = `$cmd`;
open(my $fh, '>', $outputfile) or die "Could not open file '$filename' $!";
print $fh $dlfile;
close $fh;
print "wrote $outputfile\n";



if ($mailto && $mailfrom) {
    my $olddir = getcwd;
    my $dir = `mktemp -d`;
    chomp($dir);
    chdir $dir;
    my $basename = `basename $outputfile`;
    chomp($basename);
    $basename =~ s/.nessus$//;
    my $cmd = `/opt/nessus_parser/nessus_parser.pl $outputfile`;
    my $xlsfile = "$dir" . "/" . "$basename" . ".xlsx";
    $cmd = "echo \"Nessus Sanning complete for $client.\" | /usr/bin/heirloom-mailx -S smtp=\"$smtpserver\" -a $xlsfile -r $mailfrom -s \"Nessus Scanning complete.  Please see the attached nessus report\" -c $mailfrom $mailto";
    print "Sending e-amil\n$cmd\n";
    `$cmd`;
    chdir $olddir;
}

