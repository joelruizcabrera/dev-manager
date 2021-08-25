<?php
function connectMysql() {
    define('DB_SERVER', 'localhost');
    define('DB_USERNAME', 'homestead');
    define('DB_PASSWORD', 'secret');
    define('DB_NAME', 'dev_manager');

    /* Attempt to connect to MySQL database */
    $link = mysqli_connect(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);

    // Check connection
    if($link === false){
        die("ERROR: Could not connect. " . mysqli_connect_error());
    }
    return $link;
}
?>
