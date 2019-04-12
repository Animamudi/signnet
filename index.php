
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