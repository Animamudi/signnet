
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