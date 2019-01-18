<?php

 function lcgetvar($mac,$type)
 {
	 global $snmp_host, $snmp_community, $lancomBaseOID;

	 if ($result = snmpget($snmp_host,$snmp_community,"$lancomBaseOID.$type.$mac")) {
		 return stripsnmp($result);
	 } else {
		 return FALSE;
	 }
 }

 function stripsnmp($string) 
 {

	 $result = str_replace("Hex-STRING: ", "", $string);
	 $result = str_replace("INTEGER: ", "", $result);
	 $result = str_replace("STRING: ", "", $result);
	 return $result;
 }

 function dprint ($string)
 {
	 global $debug;
	 if ($debug > 0) {
		 print "DEBUG: $string \n";
	 }
 }

 function zeropad($num, $lim)
 {
	    return (strlen($num) >= $lim) ? $num : zeropad("0" . $num,$lim);
 }

 function decmachex($dec_mac) 
 {
	 $exp_mac = explode(".",$dec_mac,6);
	 for ($i = 0; $i < 6; $i++) {
		 $tmp_mac[$i] = strtoupper(zeropad(dechex($exp_mac[$i]),2));
	 }
	 return implode(":",$tmp_mac);
 } 

 function dbEntry($sql,$hex_mac,$net_name,$rssi,$rx_phy,$age) 
 {
	 global $snmp_host;

	 $net_name = str_replace("'", "''", $net_name);
	
	 $query = "INSERT INTO seenclients(mac,netname,rssi,rxphy,age,lastseen,scanner) VALUES ('$hex_mac','$net_name',$rssi,$rx_phy,$age,NOW() - (interval '1 min' * $age),'$snmp_host')";
	 dprint ("SQL: $query");
	 return pg_query($sql,$query);
 }


 $totcount = 0;
 $newcount = 0;
 $upcount = 0;
 $expcount = 0;

 $lancomBaseOID = "iso.3.6.1.4.1.2356.11.1.3.45.1";

 $pSQL = pg_pconnect ("host=$dbHost dbname=$dbName user=$dbUser password=$dbPass");

 $seenClientsTable = snmprealwalk( $snmp_host, $snmp_community, "$lancomBaseOID.1" );

 foreach ($seenClientsTable as $oid => $value) {
	 $totcount++;
	 $dec_mac = str_replace("$lancomBaseOID.1.", "", $oid); 
	 $hex_mac = decmachex($dec_mac);
	 dprint("$hex_mac");
	 if (lcgetvar ($dec_mac, 5)) {
	   $net_name = lcgetvar ($dec_mac, 5);
	   $rssi = lcgetvar ($dec_mac, 3);
	   $age = lcgetvar ($dec_mac, 4);
	   $rx_phy = lcgetvar ($dec_mac, 6);
	   dprint(" - $net_name ($rssi/$rx_phy) $age old");
	   $dbResult = pg_query($pSQL, "select mac,age,time FROM seenclients WHERE mac = '$hex_mac' ORDER BY time DESC LIMIT 1");
	   if (pg_num_rows($dbResult) > 0) {
	      $row = pg_fetch_row($dbResult); 
	      if ($row[1] > $age || $age < 10) { 
	         dprint ("INSERTING: $row[1] > $age or $age < 10");
	         dbEntry($pSQL,$hex_mac,$net_name,$rssi,$rx_phy,$age);
	         $upcount++;
	      } 
	   } else {
	     dprint ("INSERTING: new victim");
	     dbEntry($pSQL,$hex_mac,$net_name,$rssi,$rx_phy,$age);
	     $newcount++;
	   }
	 } else {
	     $expcount++;
	     dprint (" - $hex_mac expired while running");
	 }
 }
 print "N:U:T:E $newcount:$upcount:$totcount:$expcount\n";

?>
