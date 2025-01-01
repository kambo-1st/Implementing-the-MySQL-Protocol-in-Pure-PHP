<?php

use OurMySQL\Client;

require 'client.php';

$ourmysql = new Client(
    server: 'db',
    username: 'exampleuser',
    password: 'examplepassword',
    database: 'exampledb',
    port: 3306,
);
$rows = $ourmysql->query('SELECT text, id FROM foo');
var_dump($rows);
