
<?php

/*
    This file is part of Dash Ninja.
    https://github.com/elbereth/dashninja-be

    Dash Ninja is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Dash Ninja is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Dash Ninja.  If not, see <http://www.gnu.org/licenses/>.

 */

/*****************************************************************************
 * Dash Ninja Back-end Private REST API                                      *
 *---------------------------------------------------------------------------*
 * This script is the backend interface between hubs                         *
 * It is the foundation for all other scripts, it is private API and is not  *
 * meant to be public.                                                       *
 *                                                                           *
 * Identification of peers is done via SSL client certificates               *
 *                                                                           *
 * Required:                                                                 *
 * Phalcon PHP extension - http://phalconphp.com                             *
 *****************************************************************************/

require_once('libs/db.inc.php');

// =================================================
// Authenticate the remote peer (Before the Routing)
// =================================================
// Done via the EventManager and beforeHandleRoute event

// By default peer is not authenticated:
$authinfo = false;

// Create a events manager
$eventManager = new Phalcon\Events\Manager();

// Attach the anonymous function to handle the authentication of the peer
$eventManager->attach('micro', function($event, $app) use ($mysqli) {
  global $authinfo;

  if ($event->getType() == 'beforeHandleRoute') {

    // The server should have the TLS client certificate information and the remote peer address
    // If not, just fail early
    if (!array_key_exists("VERIFIED",$_SERVER) || ($_SERVER['VERIFIED'] != "SUCCESS")
     || !array_key_exists("DN",$_SERVER) || (strlen($_SERVER['DN'])==0)
     || !array_key_exists("REMOTE_ADDR",$_SERVER) || (strlen($_SERVER['REMOTE_ADDR'])==0)) {
      $response = new Phalcon\Http\Response();
      $response->setStatusCode(401, "Unauthorized");
      //Send errors to the client
      $response->setJsonContent(array('status' => 'ERROR', 'messages' => array('Missing/Wrong TLS client certificate')));
      $response->send();
      return false;
    }
    // The server could not connect to the MySQL database
    // Means we are out of business
    elseif ($mysqli->connect_errno != 0) {
      $response = new Phalcon\Http\Response();
      //Change the HTTP status
      $response->setStatusCode(503, "Service Unavailable");
      //Send errors to the client
      $response->setJsonContent(array('status' => 'ERROR', 'messages' => array('No DB connection ('.$mysqli->connect_errno.': '.$mysqli->connect_error.')')));
      $response->send();
      return false;
    }
    // Now we need to check the peer is a known/allowed hub (via its client certificate and the remote address)
    $cacheserial = sha1($_SERVER['DN']);
    $cacheserial2 = sha1($_SERVER['REMOTE_ADDR']);
    $cachefnam = CACHEFOLDER.sprintf("dashninja_cmd_hubcheck_%s_%s",$cacheserial,$cacheserial2);
    $cachevalid = (is_readable($cachefnam) && ((filemtime($cachefnam)+7200)>=time()));
    if ($cachevalid) {
      $data = unserialize(file_get_contents($cachefnam));
      $result = $data["result"];
      $authinfo = $data["authinfo"];
    }
    else {
      $sql = "SELECT HubId, HubEnabled, HubDescription FROM cmd_hub WHERE HubCertificate = '%s' AND HubIPv6 = inet6_aton('%s')";
      $sqlx = sprintf($sql,$mysqli->real_escape_string($_SERVER['DN'])
                          ,$mysqli->real_escape_string($_SERVER['REMOTE_ADDR']));
      $result = $mysqli->query($sqlx);
      if ($result !== false) {
        // If the query is a success, we retrieve the first result (should be the only one)
        $authinfo = $result->fetch_assoc();
        $result->close();
      }
      $data = array("result" => $result, "authinfo" => $authinfo);
      file_put_contents($cachefnam,serialize($data),LOCK_EX);
    }
    // If the query failed, something is wrong with MySQL
    // Means we are out of business
    if ($result === false) {
      $response = new Phalcon\Http\Response();
      $response->setStatusCode(503, "Service Unavailable");
      $response->setJsonContent(array('status' => 'ERROR', 'messages' => array($mysqli->errno.': '.$mysqli->error)));
      $response->send();
      $authinfo = false;
      return false;
    }
    else {
      // If the query result is null, then the remote peer is NOT authorized
      if (is_null($authinfo)) {
        $response = new Phalcon\Http\Response();
        $response->setStatusCode(401, "Unauthorized");
        $response->setJsonContent(array('status' => 'ERROR', 'messages' => array('TLS client certificate did not match a known hub',$_SERVER['DN'],$_SERVER['REMOTE_ADDR'],$sql,$sqlx)));
        $response->send();
        $authinfo = false;
        return false;
      }
      // The remote is known, but disabled, deny the access
      elseif ($authinfo['HubEnabled'] != '1') {
        $response = new Phalcon\Http\Response();
        $response->setStatusCode(401, "Unauthorized");
        $response->setJsonContent(array('status' => 'ERROR', 'messages' => array('Hub is disabled (Access denied)')));
        $response->send();
        return false;
      }
      // We passed! Peer is authorized!
    }
  }

});

//Create and bind the DI to the application
$app = new \Phalcon\Mvc\Micro();
$app->setEventsManager($eventManager);

$router = $app->getRouter();
//$router->setUriSource(\Phalcon\Mvc\Router::URI_SOURCE_SERVER_REQUEST_URI);

// ============================================================================
// BALANCES (for dmnbalance)
// ----------------------------------------------------------------------------
// End-point to retrieve all pubkeys and last updates
// HTTP method:
//   GET
// Parameters:
//   None
// ============================================================================
$app->get('/balances', function() use ($app,&$mysqli) {

  global $authinfo;

  //Create a response
  $response = new Phalcon\Http\Response();

  $request = $app->request;

  if (!array_key_exists('CONTENT_LENGTH',$_SERVER) || (intval($_SERVER['CONTENT_LENGTH']) != 0)) {
    //Change the HTTP status
    $response->setStatusCode(400, "Bad Request");
    //Send errors to the client
    $response->setJsonContent(array('status' => 'ERROR', 'messages' => array('Payload (or CONTENT_LENGTH) is missing')));
  }
  else {
    // Retrieve all known nodes for current hub
    $sql = "SELECT TestNet, PubKey, LastUpdate FROM cmd_info_masternode_balance";
    $mnpubkeys = array();
    $tnpubkeys = array();
    if ($result = $mysqli->query($sql)) {
      while($row = $result->fetch_assoc()){
        $date = new DateTime($row['LastUpdate']);
        $row['LastUpdate'] = $date->getTimestamp();
        if ($row['TestNet'] == 1) {
          $tnpubkeys[$row['PubKey']] = $row['LastUpdate'];
        }
        else {
          $mnpubkeys[$row['PubKey']] = $row['LastUpdate'];
       }
      }

      //Change the HTTP status
      $response->setStatusCode(200, "OK");
      $response->setJsonContent(array('status' => 'OK', 'data' => array('balances' => array('testnet' => $tnpubkeys,
                                                                                            'mainnet' => $mnpubkeys))));
    }
    else {
      $response->setStatusCode(503, "Service Unavailable");
      $response->setJsonContent(array('status' => 'ERROR', 'messages' => array($mysqli->errno.': '.$mysqli->error)));
    }
  }
  return $response;

});

// ============================================================================
// BALANCES (Reporting for dmnbalance)
// ----------------------------------------------------------------------------
// End-point for the balance report
// HTTP method:
//   POST
// Parameters (JSON body):
//   array of balance information (mandatory)
// Result (JSON body):
//   status=OK|ERROR
//   messages=array of error messages (only if status is ERROR)
//   data=array of insert/update information (only if status is OK)
// ============================================================================
$app->post('/balances', function() use ($app,&$mysqli) {

  global $authinfo;

  //Create a response
  $response = new Phalcon\Http\Response();

  $payload = $app->request->getRawBody();
  $payload = json_decode($payload,true);

  if (!array_key_exists('CONTENT_LENGTH',$_SERVER) || (intval($_SERVER['CONTENT_LENGTH']) == 0)
   || !is_array($payload) || (count($payload) == 0)) {
    //Change the HTTP status
    $response->setStatusCode(400, "Bad Request");

    //Send errors to the client
    $response->setJsonContent(array('status' => 'ERROR', 'messages' => array('Payload is wrong or CONTENT_LENGTH is missing')));
  }
  else {

    $sqlbal = array();
    foreach($payload as $node) {
      $sqlbal[] = sprintf("(%d,'%s',%.9f,'%s')",
                                  $node['TestNet'],
                                  $mysqli->real_escape_string($node['PubKey']),
                                  $node['Balance'],
                                  $mysqli->real_escape_string($node['LastUpdate'])
                                );
    }

    $sql = "INSERT INTO cmd_info_masternode_balance (TestNet, PubKey, Balance, LastUpdate)"
                           ." VALUES ".implode(',',$sqlbal)
            ." ON DUPLICATE KEY UPDATE Balance = VALUES(Balance), LastUpdate = VALUES(LastUpdate)";

    if ($result = $mysqli->query($sql)) {
      $info = $mysqli->info;
      if (is_null($info)) {
        $info = true;
      }

      //Change the HTTP status
      $response->setStatusCode(202, "Accepted");
      $response->setJsonContent(array('status' => 'OK', 'data' => array('balances' => $info)));

    }
    else {
      $response->setStatusCode(503, "Service Unavailable");
      $response->setJsonContent(array('status' => 'ERROR', 'messages' => array($mysqli->errno.': '.$mysqli->error)));
    }
  }
  return $response;

});

// ============================================================================
// BLOCKSGAPS (data for dmnblockdegapper)
// ----------------------------------------------------------------------------
// End-point for the balance report
// HTTP method:
//   GET
// Parameters (JSON body):
//   testnet=0|1
//   interval=interval (optional, default is P1D for 1 day)
// Result (JSON body):
//   status=OK|ERROR
//   messages=array of error messages (only if status is ERROR)
//   data=array of blocks (only is status is OK)
// ============================================================================
$app->get('/blocksgaps', function() use ($app,&$mysqli) {

    //Create a response
    $response = new Phalcon\Http\Response();

    $request = $app->request;

    $errmsg = array();

    if (!array_key_exists('CONTENT_LENGTH',$_SERVER) || (intval($_SERVER['CONTENT_LENGTH']) != 0)) {
        $errmsg[] = "No CONTENT expected";
    }

    // Retrieve the 'testnet' parameter
    if ($request->hasQuery('testnet')) {
        $testnet = intval($request->getQuery('testnet'));
        if (($testnet != 0) && ($testnet != 1)) {
            $testnet = 0;
        }
    }
    else {
        $testnet = 0;
    }

    // Retrieve the 'interval' parameter
    if ($request->hasQuery('interval')) {
        try {
            $interval = new DateInterval($request->getQuery('interval'));
        } catch (Exception $e) {
            $errmsg[] = 'Wrong interval parameter';
            $interval = new DateInterval('P1M');
        }
    }
    else {
        $interval = new DateInterval('P1M');
    }
    $interval->invert = 1;
    $datefrom = new DateTime();
    $datefrom->add( $interval );
    $datefrom = $datefrom->getTimestamp();

    if (count($errmsg) > 0) {
        //Change the HTTP status
        $response->setStatusCode(400, "Bad Request");

        //Send errors to the client
        $response->setJsonContent(array('status' => 'ERROR', 'messages' => $errmsg));
    }
    else {
        $sql = sprintf("SELECT BlockId FROM cmd_info_blocks WHERE BlockTestNet = %d AND BlockTime >= %d ORDER BY BlockId DESC",$testnet,$datefrom);
        $blocks = array();
        if ($result = $mysqli->query($sql)) {
            while($row = $result->fetch_array(MYSQLI_NUM)){
                $blocks[intval($row[0])] = intval($row[0]);
            }

            //Change the HTTP status
            $response->setStatusCode(200, "OK");
            $response->setJsonContent(array('status' => 'OK', 'data' => $blocks));
        }
        else {
            $response->setStatusCode(503, "Service Unavailable");
            $response->setJsonContent(array('status' => 'ERROR', 'messages' => array($mysqli->errno.': '.$mysqli->error)));
        }
    }
    return $response;

});

// ============================================================================
// BLOCKS (Reporting for dmnblockparser)
// ----------------------------------------------------------------------------
// End-point for the balance report
// HTTP method:
//   POST
// Parameters (JSON body):
//   array of:
//     blockshistory (mandatory, can be empty array)
//     blocksinfo (mandatory, can be empty array)
//   (Both cannot be empty)
// Result (JSON body):
//   status=OK|ERROR
//   messages=array of error messages (only if status is ERROR)
//   data=array of insert/update information (only if status is OK)
// ============================================================================
$app->post('/blocks', function() use ($app,&$mysqli) {

  global $authinfo;

  //Create a response
  $response = new Phalcon\Http\Response();

  $payload = $app->request->getRawBody();
  $payload = json_decode($payload,true);

  if (!array_key_exists('CONTENT_LENGTH',$_SERVER) || (intval($_SERVER['CONTENT_LENGTH']) == 0)
   || !is_array($payload) || !array_key_exists('blockshistory',$payload) || !is_array($payload['blockshistory'])
   || !array_key_exists('blocksinfo',$payload) || !is_array($payload['blocksinfo'])
   || ((count($payload['blockshistory']) == 0) && (count($payload['blocksinfo']) == 0))) {
    //Change the HTTP status
    $response->setStatusCode(400, "Bad Request");

    //Send errors to the client
    $response->setJsonContent(array('status' => 'ERROR', 'messages' => array('Payload is wrong or CONTENT_LENGTH is missing',"cbh=".count($payload['blockshistory'])." cbi=".count($payload['blocksinfo']),var_export($payload,true))));
  }
  else {
    // Retrieve all known nodes for current hub
    $result = dashninja_cmd_getnodes($mysqli,$authinfo['HubId'],0);
    $numnodes = 0;
    $nodes = array();
    if (count($result) > 0) {
      foreach($result as $nodename => $row){
        $numnodes++;
        $nodes[$nodename] = $row['NodeId'];
      }
    }
    $result = dashninja_cmd_getnodes($mysqli,$authinfo['HubId'],1);
    if (count($result) > 0) {
        foreach($result as $nodename => $row){
            $numnodes++;
            $nodes[$nodename] = $row['NodeId'];
        }
    }
    if ($numnodes == 0) {
      $response->setStatusCode(503, "Service Unavailable");
      $response->setJsonContent(array('status' => 'ERROR', 'messages' => array('No nodes found')));
    }
    else {
      $stats = array();
      $bhsql = array();
      $curratio = array(-1,-1);
      foreach($payload['blockshistory'] as $bhentry) {
        if (!array_key_exists($bhentry['FromNodeUserName'],$nodes)) {
          $response->setStatusCode(503, "Service Unavailable");
          $response->setJsonContent(array('status' => 'ERROR', 'messages' => array("Unknown node reported")));
          return $response;
        }
        $bhsql[] = sprintf("(%d,%d,%d,'%s','%s',%d,%.8f)",$bhentry['BlockHeight'],
                                                     $bhentry['BlockTestNet'],
                                                     $nodes[$bhentry['FromNodeUserName']],
                                                     $mysqli->real_escape_string($bhentry['BlockMNPayee']),
                                                     $mysqli->real_escape_string($bhentry['LastUpdate']),
                                                     $bhentry['Protocol'],
                                                     $bhentry['BlockMNRatio']);
        if ($bhentry['BlockMNRatio'] > $curratio[$bhentry['BlockTestNet']]) {
          $curratio[$bhentry['BlockTestNet']] = $bhentry['BlockMNRatio'];
        }
      }
      $bhinfo = false;
      if (count($bhsql) > 0) {
        $sql = "INSERT INTO cmd_info_blocks_history2 (BlockHeight, BlockTestNet, NodeID, BlockMNPayee, LastUpdate, Protocol, BlockMNRatio)"
                         ." VALUES ".implode(',',$bhsql)
              ." ON DUPLICATE KEY UPDATE BlockMNPayee = VALUES(BlockMNPayee), LastUpdate = VALUES(LastUpdate), Protocol = VALUES(Protocol), BlockMNRatio = VALUES(BlockMNRatio)";

        if ($result = $mysqli->query($sql)) {
          $bhinfo = $mysqli->info;
          if (is_null($bhinfo)) {
            $bhinfo = true;
          }
        }
        else {
          $response->setStatusCode(503, "Service Unavailable");
          $response->setJsonContent(array('status' => 'ERROR', 'messages' => array($mysqli->errno.': '.$mysqli->error)));
          return $response;
        }
        if ($curratio[0] > -1) {
          $stats[] = sprintf("('mnpaymentratio','%s',%d,'dashninja')",$curratio[0],time());
        }
        if ($curratio[1] > -1) {
          $stats[] = sprintf("('mnpaymentratiotest','%s',%d,'dashninja')",$curratio[1],time());
        }
      }

      $bisql = array();
      $bsbsql = array();
      $mninfo = array();
      $sqlwheretemplate = "(BlockHeight = %d AND BlockTestNet = %d)";
      $sqlwhere = array();
      foreach($payload['blocksinfo'] as $bientry) {
        $sqlwhere[] = sprintf($sqlwheretemplate,$bientry['BlockId'],$bientry['BlockTestNet']);
      }
      $sql = <<<EOT
DROP TABLE IF EXISTS _cibh_nodecount;
CREATE TEMPORARY TABLE IF NOT EXISTS
    _cibh_nodecount ENGINE=MEMORY AS (
                        SELECT
                                MP.BlockHeight BlockHeight,
                                BlockMNPayee,
                                COUNT(NodeID) CountNode,
                                MAX(BlockMNRatio) BlockMNRatio
                        FROM
                                (SELECT
                                        BlockHeight,
                                        MAX(Protocol) Protocol
                                FROM
                                        cmd_info_blocks_history2
                                WHERE
					%s
                                GROUP BY
                                        BlockHeight
                                ) MP
                        LEFT JOIN
                                cmd_info_blocks_history2 cibh
                                ON
                                        (cibh.BlockHeight=MP.BlockHeight
                                        AND cibh.Protocol=MP.Protocol)
                                GROUP BY
                                        BlockHeight,
                                        BlockMNPayee
                        );
DROP TABLE IF EXISTS _cibh_maxnodecount;
CREATE TEMPORARY TABLE IF NOT EXISTS _cibh_maxnodecount ENGINE=MEMORY AS (
        SELECT
                BlockHeight,
                MAX(CountNode) MaxCountNode
        FROM
                _cibh_nodecount
        GROUP BY
                BlockHeight
        );
SELECT NC.BlockHeight BlockHeight, BlockMNPayee, BlockMNRatio FROM _cibh_maxnodecount MNC, _cibh_nodecount NC WHERE MNC.BlockHeight = NC.BlockHeight AND MNC.MaxCountNode = NC.CountNode;
EOT;

        $sql = sprintf($sql,implode(" OR ",$sqlwhere));
        $blockhist = array();
        if ($mysqli->multi_query($sql) &&
            $mysqli->more_results() && $mysqli->next_result() &&
            $mysqli->more_results() && $mysqli->next_result() &&
            $mysqli->more_results() && $mysqli->next_result() &&
            $mysqli->more_results() && $mysqli->next_result() &&
            ($result = $mysqli->store_result())) {
          while($row = $result->fetch_assoc()){
            $blockhist[intval($row['BlockHeight'])] = array("BlockMNValueRatioExpected" => floatval($row['BlockMNRatio']),
                                                            "BlockMNPayeeExpected" => $row['BlockMNPayee']);
          }
        }

      foreach($payload['blocksinfo'] as $bientry) {
          // Force actual 50% is value is 0% by mistake (block history is wrong, node was down at that time probably...)
          if ($blockhist[intval($bientry['BlockId'])]['BlockMNValueRatioExpected'] <= 0) {
              $blockhist[intval($bientry['BlockId'])]['BlockMNValueRatioExpected'] = 0.5;
          }

        $bisql[] = sprintf("(%d,%d,'%s','%s',%.9f,%.9f,%d,'%s',%d,%d,%.9f,%d,'%s',%.9f,%d,'%s',%d,%d,%d,%.9f,%d)",$bientry['BlockTestNet'],
                                                     $bientry['BlockId'],
                                                     $mysqli->real_escape_string($bientry['BlockHash']),
                                                     $mysqli->real_escape_string($bientry['BlockMNPayee']),
                                                     $bientry['BlockMNValue'],
                                                     $bientry['BlockSupplyValue'],
                                                     $bientry['BlockMNPayed'],
                                                     $mysqli->real_escape_string($bientry['BlockPoolPubKey']),
                                                     $bientry['BlockMNProtocol'],
                                                     $bientry['BlockTime'],
                                                     $bientry['BlockDifficulty'],
                                                     $bientry['BlockMNPayeeDonation'],
                                                     $mysqli->real_escape_string($blockhist[intval($bientry['BlockId'])]['BlockMNPayeeExpected']),
                                                     $blockhist[intval($bientry['BlockId'])]['BlockMNValueRatioExpected'],
            $bientry['IsSuperblock'],
            $mysqli->real_escape_string($bientry['SuperblockBudgetName']),
            $bientry['BlockDarkSendTXCount'],
            $bientry['MemPoolDarkSendTXCount'],
            $bientry['SuperblockBudgetPayees'],
            $bientry['SuperblockBudgetAmount'],
            $bientry['BlockVersion']
        );
        if ((array_key_exists($bientry['BlockMNPayee'].":".$bientry['BlockTestNet'],$mninfo) && ($mninfo[$bientry['BlockMNPayee'].":".$bientry['BlockTestNet']] < $bientry['BlockId']))
         || !(array_key_exists($bientry['BlockMNPayee'].":".$bientry['BlockTestNet'],$mninfo))) {
          $mninfo[$bientry['BlockMNPayee'].":".$bientry['BlockTestNet']] = $bientry['BlockId'];
        }
        if (array_key_exists("SuperblockDetails",$bientry) && (is_array($bientry["SuperblockDetails"])) && (count($bientry["SuperblockDetails"]) > 0)) {
            foreach($bientry["SuperblockDetails"] as $item) {
                $bsbsql[] = sprintf("(%d,%d,'%s',%.9f,'%s')",$bientry['BlockTestNet'],
                    $bientry['BlockId'],
                    $mysqli->real_escape_string($item['GovernanceObjectPaymentAddress']),
                    floatval($item['GovernanceObjectPaymentAmount']),
                    $mysqli->real_escape_string($item['GovernanceObjectPaymentProposalHash']));
            }
        }
      }
      $mninfosql = array();
      foreach($mninfo as $rawkey => $mnblock) {
        $mnkey = explode(":",$rawkey);
        $mninfosql[] = sprintf("(%d,'%s',%d)",$mnkey[1],
                                              $mysqli->real_escape_string($mnkey[0]),
                                              $mnblock);
      }
      $biinfo = false;
      $mninfoinfo = false;
      if (count($bisql) > 0) {
        $sql = "INSERT INTO cmd_info_blocks (BlockTestNet, BlockId, BlockHash, BlockMNPayee, BlockMNValue, BlockSupplyValue, BlockMNPayed, "
              ."BlockPoolPubKey, BlockMNProtocol, BlockTime, BlockDifficulty, BlockMNPayeeDonation, BlockMNPayeeExpected, BlockMNValueRatioExpected, IsSuperblock, SuperblockBudgetName, "
              ."BlockDarkSendTXCount, MemPoolDarkSendTXCount, SuperblockBudgetPayees, SuperblockBudgetAmount, BlockVersion)"
              ." VALUES ".implode(',',$bisql)
              ." ON DUPLICATE KEY UPDATE BlockHash = VALUES(BlockHash), BlockMNPayee = VALUES(BlockMNPayee), BlockMNValue = VALUES(BlockMNValue),"
              ." BlockSupplyValue = VALUES(BlockSupplyValue), BlockMNPayed = VALUES(BlockMNPayed), BlockPoolPubKey = VALUES(BlockPoolPubKey),"
              ." BlockMNProtocol = VALUES(BlockMNProtocol), BlockTime = VALUES(BlockTime), BlockDifficulty = VALUES(BlockDifficulty),"
              ." BlockMNPayeeDonation = VALUES(BlockMNPayeeDonation), BlockMNPayeeExpected = VALUES(BlockMNPayeeExpected),"
              ." BlockMNValueRatioExpected = VALUES(BlockMNValueRatioExpected), IsSuperblock = VALUES(IsSuperblock), SuperblockBudgetName = VALUES(SuperblockBudgetName),"
              ." BlockDarkSendTXCount = VALUES(BlockDarkSendTXCount), MemPoolDarkSendTXCount = VALUES(MemPoolDarkSendTXCount),"
              ." SuperblockBudgetPayees = VALUES(SuperblockBudgetPayees), SuperblockBudgetAmount = VALUES(SuperblockBudgetAmount),"
              ." BlockVersion = VALUES(BlockVersion)";

        if ($result = $mysqli->query($sql)) {
          $biinfo = $mysqli->info;
          if (is_null($biinfo)) {
            $biinfo = true;
          }
        }
        else {
          $response->setStatusCode(503, "Service Unavailable");
          $response->setJsonContent(array('status' => 'ERROR', 'messages' => array($mysqli->errno.': '.$mysqli->error)));
          return $response;
        }
        $mninfores = 0;
        $debugtxt = "";
        $sql = "INSERT INTO cmd_info_masternode_lastpaid (MNTestNet, MNPubKey, MNLastPaidBlock) VALUES ".implode(',',$mninfosql)
               ." ON DUPLICATE KEY UPDATE MNLastPaidBlock = VALUES(MNLastPaidBlock)";
        if ($result = $mysqli->query($sql)) {
          $mninfoinfo = $mysqli->info;
          if (is_null($biinfo)) {
            $mninfoinfo = true;
          }
        }
        else {
          $response->setStatusCode(503, "Service Unavailable");
          $response->setJsonContent(array('status' => 'ERROR', 'messages' => array($mysqli->errno.': '.$mysqli->error)));
          return $response;
        }

        $interval = new DateInterval('P1D');
        $interval->invert = 1;
        $datefrom = new DateTime();
        $datefrom->add( $interval );
        $datefrom = $datefrom->getTimestamp();

        $sql = sprintf("SELECT `BlockTestNet`, SUM(`BlockSupplyValue`) TotalSupplyValue, SUM(`BlockMNValue`) TotalMNValue, COUNT(1) NumBlocks, SUM(BlockMNPayed) NumPayed FROM `cmd_info_blocks` WHERE BlockTime >= %d GROUP BY `BlockTestNet`",$datefrom);
        if ($result = $mysqli->query($sql)) {
          while($row = $result->fetch_assoc()){
            $statkey = "last24hsupply";
            if ($row["BlockTestNet"] == 1) {
              $statkey .= "test";
            }
            $stats[] = sprintf("('%s','%s',%d,'dashninja')",$statkey,$row["TotalSupplyValue"],time());
            $statkey = "paymentdrk";
            if ($row["BlockTestNet"] == 1) {
              $statkey .= "test";
            }
            $stats[] = sprintf("('%s','%s',%d,'dashninja')",$statkey,$row["TotalMNValue"],time());
            $statkey = "mnpayments";
            if ($row["BlockTestNet"] == 1) {
              $statkey .= "test";
            }
            $stats[] = sprintf("('%s','%s',%d,'dashninja')",$statkey,round(($row["NumPayed"]/$row["NumBlocks"])*100,2),time());
          }
        }
      }

      if (count($stats) > 0) {
        $sql = "INSERT INTO cmd_stats_values (StatKey, StatValue, LastUpdate, Source)"
             ." VALUES ".implode(',',$stats)
             ." ON DUPLICATE KEY UPDATE StatValue = VALUES(StatValue), LastUpdate = VALUES(LastUpdate), Source = VALUES(Source)";

        if ($result = $mysqli->query($sql)) {
          $statsinfo = $mysqli->info;
          if (is_null($biinfo)) {
            $statsinfo = true;
          }
        }
        else {
          $response->setStatusCode(503, "Service Unavailable");
          $response->setJsonContent(array('status' => 'ERROR', 'messages' => array($mysqli->errno.': '.$mysqli->error)));
          return $response;
        }
      }

      $superblockinfo = false;
      if (count($bsbsql) > 0) {
          $sql = "INSERT INTO cmd_info_blocks_superblockpayments (BlockTestNet, BlockId, GovernanceObjectPaymentAddress, GovernanceObjectPaymentAmount, GovernanceObjectPaymentProposalHash)"
              . " VALUES " . implode(',', $bsbsql)
              . " ON DUPLICATE KEY UPDATE GovernanceObjectPaymentAddress = VALUES(GovernanceObjectPaymentAddress), GovernanceObjectPaymentAmount = VALUES(GovernanceObjectPaymentAmount)";

          if ($result = $mysqli->query($sql)) {
              $superblockinfo = $mysqli->info;
              if (is_null($biinfo)) {
                  $superblockinfo = true;
              }
          } else {
              $response->setStatusCode(503, "Service Unavailable");
              $response->setJsonContent(array('status' => 'ERROR', 'messages' => array($mysqli->errno . ': ' . $mysqli->error)));
              return $response;
          }
      }

      //Change the HTTP status
      $response->setStatusCode(202, "Accepted");
      $response->setJsonContent(array('status' => 'OK', 'data' => array('blockshistory' => $bhinfo,
                                                                        'blocksinfo' => $biinfo,
                                                                        'superblockdetailsinfo' => $superblockinfo,
                                                                        'mninfo' => $mninfoinfo)));

    }
  }
  return $response;

});

// ============================================================================
// BUDGETS EXPECTED (for dmnblockparser)
// ----------------------------------------------------------------------------
// End-point to retrieve all expected superblocks
// HTTP method:
//   GET
// Parameters:
//   None
// ============================================================================
$app->get('/budgetsexpected', function() use ($app,&$mysqli) {

    //Create a response
    $response = new Phalcon\Http\Response();

    if (!array_key_exists('CONTENT_LENGTH',$_SERVER) || (intval($_SERVER['CONTENT_LENGTH']) != 0)) {
        //Change the HTTP status
        $response->setStatusCode(400, "Bad Request");
        //Send errors to the client
        $response->setJsonContent(array('status' => 'ERROR', 'messages' => array('Payload (or CONTENT_LENGTH) is missing')));
    }
    else {
        // Retrieve all known final budgets
        $sql = 'SELECT BudgetTestnet, BlockStart, BlockEnd, Proposals FROM cmd_budget_final WHERE VoteCount > 0 AND (IsValid = 1 OR IsValidReason = "Older than current blockHeight") AND Status = "OK"';
        $mnbudgets = array(array(),array());
        $proposalsfinal = array(array(),array());
        if ($result = $mysqli->query($sql)) {
            while($row = $result->fetch_assoc()){
                $pos = 0;
                $proposals = explode(",",$row['Proposals']);
                for ($x = intval($row['BlockStart']);$x <= intval($row['BlockEnd']); $x++) {
                    $mnbudgets[$row['BudgetTestnet']][$x] = array(
                        "BlockId" => $x,
                        "BlockProposal" => $proposals[$pos]
                    );
                    $proposalsfinal[$row['BudgetTestnet']][] = $proposals[$pos];
                    $pos++;
                }
            }

            $proposalsvalues = array(array(),array());
            $sql = "SELECT BudgetTestnet, BudgetId, MonthlyPayment, PaymentAddress FROM cmd_budget_projection";
            if ($result = $mysqli->query($sql)) {
                $test = array();
                while ($row = $result->fetch_assoc()) {
                    $test[] = $row;
                    if (in_array($row['BudgetId'], $proposalsfinal[$row['BudgetTestnet']])) {
                        $proposalsvalues[$row['BudgetTestnet']][$row['BudgetId']] = $row;
                    }
                }

                foreach ($mnbudgets as $mnbudgetestnet => $mnbudgetdata) {
                    foreach ($mnbudgetdata as $mnbudgetdataid => $mnbudgetdatadata) {
                        if (array_key_exists($mnbudgetdatadata["BlockProposal"], $proposalsvalues[$mnbudgetestnet])) {
                            $mnbudgets[$mnbudgetestnet][$mnbudgetdataid]["MonthlyPayment"] = $proposalsvalues[$mnbudgetestnet][$mnbudgetdatadata["BlockProposal"]]["MonthlyPayment"];
                            $mnbudgets[$mnbudgetestnet][$mnbudgetdataid]["PaymentAddress"] = $proposalsvalues[$mnbudgetestnet][$mnbudgetdatadata["BlockProposal"]]["PaymentAddress"];
                        } else {
                            $mnbudgets[$mnbudgetestnet][$mnbudgetdataid]["MonthlyPayment"] = 0.0;
                            $mnbudgets[$mnbudgetestnet][$mnbudgetdataid]["PaymentAddress"] = "";
                        };
                    }
                }

                //Change the HTTP status
                $response->setStatusCode(200, "OK");
                $response->setJsonContent(array('status' => 'OK', 'data' => array('budgetsexpected' => $mnbudgets)));
            }
        else {
            $response->setStatusCode(503, "Service Unavailable");
            $response->setJsonContent(array('status' => 'ERROR', 'messages' => array($mysqli->errno . ': ' . $mysqli->error)));

        }
        }
        else {
            $response->setStatusCode(503, "Service Unavailable");
            $response->setJsonContent(array('status' => 'ERROR', 'messages' => array($mysqli->errno.': '.$mysqli->error)));
        }
    }
    return $response;

});

// ============================================================================
// SUPERBLOCK PAYMENTS EXPECTED (for dmnblockparser)
// ----------------------------------------------------------------------------
// End-point to retrieve all expected superblocks payments (v12.1+)
// HTTP method:
//   GET
// Parameters:
//   None
// ============================================================================
$app->get('/superblocksexpected', function() use ($app,&$mysqli) {

    //Create a response
    $response = new Phalcon\Http\Response();

    if (!array_key_exists('CONTENT_LENGTH',$_SERVER) || (intval($_SERVER['CONTENT_LENGTH']) != 0)) {
        //Change the HTTP status
        $response->setStatusCode(400, "Bad Request");
        //Send errors to the client
        $response->setJsonContent(array('status' => 'ERROR', 'messages' => array('Payload (or CONTENT_LENGTH) is missing')));
    }
    else {
        // Retrieve all known final budgets
        $sql = 'SELECT cgot.GovernanceObjectTestnet TestNet, cgot.GovernanceObjectEventBlockHeight BlockHeight, cgotp.GovernanceObjectPaymentAddress '
              .'ProposalPaymentAddress, cgotp.GovernanceObjectPaymentAmount ProposalPaymentAmount, cgotp.GovernanceObjectPaymentProposalHash '
              .'ProposalHash FROM cmd_gobject_triggers cgot LEFT OUTER JOIN cmd_gobject_triggers_payments cgotp '
              .'ON cgot.GovernanceObjectTestnet = cgotp.GovernanceObjectTestnet AND cgot.GovernanceObjectId = cgotp.GovernanceObjectId '
              .'WHERE cgot.GovernanceObjectVotesAbsoluteYes > 0 AND cgot.GovernanceObjectCachedFunding = 1';
        $mnsuperblocks = array(array(),array());
        if ($result = $mysqli->query($sql)) {
            while($row = $result->fetch_assoc()){
                $row["TestNet"] = intval($row["TestNet"]);
                $row["BlockHeight"] = intval($row["BlockHeight"]);
                if (array_key_exists($row['BlockHeight'],$mnsuperblocks[$row["TestNet"]])) {
                    $mnsuperblocks[$row["TestNet"]][$row["BlockHeight"]]["ProposalPayments"][] = array(
                            "ProposalPaymentAddress" => $row["ProposalPaymentAddress"],
                            "ProposalPaymentAmount" => $row["ProposalPaymentAmount"],
                            "ProposalHash" => $row["ProposalHash"]
                    );
                }
                else {
                    $mnsuperblocks[$row["TestNet"]][$row["BlockHeight"]] = array(
                      "BlockHeight" => $row["BlockHeight"],
                      "ProposalPayments" => array(array(
                          "ProposalPaymentAddress" => $row["ProposalPaymentAddress"],
                          "ProposalPaymentAmount" => $row["ProposalPaymentAmount"],
                          "ProposalHash" => $row["ProposalHash"]
                      ))
                    );
                }
            }

            //Change the HTTP status
            $response->setStatusCode(200, "OK");
            $response->setJsonContent(array('status' => 'OK', 'data' => array('superblocksexpected' => $mnsuperblocks)));
        }
        else {
            $response->setStatusCode(503, "Service Unavailable");
            $response->setJsonContent(array('status' => 'ERROR', 'messages' => array($mysqli->errno.': '.$mysqli->error)));
        }
    }
    return $response;

});

// Function to retrieve the masternode list
function dashninja_masternodes_get($mysqli, $testnet = 0, $protocol = 0) {

  $sqlmaxprotocol = sprintf("SELECT MAX(NodeProtocol) Protocol FROM cmd_nodes cn, cmd_nodes_status cns WHERE cn.NodeId = cns.NodeId AND NodeTestnet = %d GROUP BY NodeTestnet",$testnet);
  // Run the query
  if ($result = $mysqli->query($sqlmaxprotocol)) {
    $row = $result->fetch_assoc();
    $protocol = 0;
    if ($row !== false) {
      $protocol = $row['Protocol'];
    }
  }
  else {
    $response->setStatusCode(503, "Service Unavailable");
    $response->setJsonContent(array('status' => 'ERROR', 'messages' => array($mysqli->errno.': '.$mysqli->error)));
    return $response;
  }

  $sqlprotocol = sprintf(" AND cns.NodeProtocol = %d",$protocol);
  $sqltestnet = sprintf("MNTestNet = %d",$testnet);

  // Retrieve the number of time each masternode is seen as active or current
  $sqlactive = "(SELECT MasternodeIP, MasternodePort, MNTestNet, COUNT(1) ActiveCount FROM cmd_info_masternode_list ciml, cmd_nodes_status cns"
              ." WHERE ciml.NodeID = cns.NodeID"
              ." AND $sqltestnet"
              ." AND (MasternodeStatus = 'active' OR MasternodeStatus = 'current')"
              .$sqlprotocol
              ." GROUP BY MasternodeIP, MasternodePort, MNTestNet) mnactive";

  // Retrieve the number of time each masternode is seen as inactive
  $sqlinactive = "(SELECT MasternodeIP, MasternodePort, MNTestNet, COUNT(1) InactiveCount FROM cmd_info_masternode_list ciml, cmd_nodes_status cns"
              ." WHERE ciml.NodeID = cns.NodeID"
              ." AND $sqltestnet"
              ." AND MasternodeStatus = 'inactive'"
              .$sqlprotocol
              ." GROUP BY MasternodeIP, MasternodePort, MNTestNet) mninactive";

  // Retrieve the number of time each masternode is not seen (unlisted)
  $sqlunlisted = "(SELECT MasternodeIP, MasternodePort, MNTestNet, COUNT(1) UnlistedCount FROM cmd_info_masternode_list ciml, cmd_nodes_status cns"
              ." WHERE ciml.NodeID = cns.NodeID"
              ." AND $sqltestnet"
              ." AND MasternodeStatus = 'unlisted'"
              .$sqlprotocol
              ." GROUP BY MasternodeIP, MasternodePort, MNTestNet) mnunlisted";

  // Retrieve only the masternodes which are active or inactive (no need for fully unlisted)
  $sql = "SELECT inet_ntoa(cim.MasternodeIP) MasternodeIP, cim.MasternodePort MasternodePort, cim.MNTestNet MNTestNet, cimpk.MNPubKey MNPubKey FROM cmd_info_masternode cim, cmd_info_masternode_pubkeys cimpk"
        ." LEFT JOIN $sqlactive USING (MasternodeIP, MasternodePort, MNTestNet)"
        ." LEFT JOIN $sqlinactive USING (MasternodeIP, MasternodePort, MNTestNet)"
        ." LEFT JOIN $sqlunlisted USING (MasternodeIP, MasternodePort, MNTestNet)"
        ." WHERE cim.MasternodeIP = cimpk.MasternodeIP AND cim.MasternodePort = cimpk.MasternodePort AND cim.MNTestNet = cimpk.MNTestNet AND cim.$sqltestnet AND ((ActiveCount > 0) OR (InactiveCount > 0)) AND cimpk.MNLastReported = 1";

  // Execute the query
  $numnodes = 0;
  if ($result = $mysqli->query($sql)) {
    $nodes = array();
    while($row = $result->fetch_assoc()){
      $numnodes++;
      $nodes[] = $row;
    }
  }
  else {
    $nodes = false;
  }

  return $nodes;
}

// Function to retrieve the masternode list
function dmn_masternodes2_get($mysqli, $testnet = 0, $protocol = 0, $mnpubkeys = array(), $mnips = array(), $mnvins = array()) {

    $sqlprotocol = sprintf("%d",$protocol);
    $sqltestnet = sprintf("%d",$testnet);

        // Add selection by pubkey
        $sqlpks = "";
        if (count($mnpubkeys) > 0) {
            $sqls = '';
            foreach($mnpubkeys as $mnpubkey) {
                if (strlen($sqls)>0) {
                    $sqls .= ' OR ';
                }
                $sqls .= sprintf("cim.MasternodePubkey = '%s'",$mysqli->real_escape_string($mnpubkey));
            }
            $sqlpks = " AND (".$sqls.")";
        }

        // Add selection by IP:port
        $sqlips = "";
        if (count($mnips) > 0) {
            $sqls = '';
            foreach($mnips as $mnip) {
                if (strlen($sqls)>0) {
                    $sqls .= ' OR ';
                }
                $sqls .= sprintf("(cim.MasternodeIPv6 = INET6_ATON('%s') AND cim.MasternodePort = %d)",$mysqli->real_escape_string($mnip[0]),$mnip[1]);
            }
            $sqlips = " AND (".$sqls.")";
        }

        // Add selection by Output-Index
        $sqlvins = "";
        if (count($mnvins) > 0) {
            $sqls = '';
            foreach($mnvins as $mnvin) {
                $mnoutput = explode('-',$mnvin);
                if (strlen($sqls)>0) {
                    $sqls .= ' OR ';
                }
                $sqls .= sprintf("(cim.MasternodeOutputHash = '%s' AND cim.MasternodeOutputIndex = %d)",$mysqli->real_escape_string($mnoutput[0]),$mnoutput[1]);
            }
            $sqlvins = " AND (".$sqls.")";
        }

        $sql = <<<EOT
SELECT
    cim.MasternodeOutputHash MasternodeOutputHash,
    cim.MasternodeOutputIndex MasternodeOutputIndex,
    inet6_ntoa(cim.MasternodeIPv6) AS MasternodeIP,
    cim.MasternodeTor MasternodeTor,
    cim.MasternodePort MasternodePort,
    cim.MasternodePubkey MasternodePubkey,
    cim.MasternodeProtocol MasternodeProtocol,
    MasternodeLastSeen,
    MasternodeActiveSeconds,
    MasternodeLastPaid,
    ActiveCount,
    InactiveCount,
    UnlistedCount,
    cimlp.MNLastPaidBlock MasternodeLastPaidBlockHeight,
    cib.BlockTime MasternodeLastPaidBlockTime,
    cib.BlockMNValue MasternodeLastPaidBlockAmount
FROM
    (cmd_info_masternode2 cim,
    cmd_info_masternode_active cima)