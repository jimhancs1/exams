<?php
/**
 * connect.php
 *
 * This file establishes a connection to the MySQL database.
 *
 * IMPORTANT:
 * Replace the placeholder values for DB_SERVER, DB_USERNAME, DB_PASSWORD,
 * and DB_NAME with your actual database credentials.
 *
 * Basic error handling is included to check if the connection was successful.
 */

define('DB_SERVER', 'localhost'); // Your MySQL server host (e.g., 'localhost' or an IP address)
define('DB_USERNAME', 'school_admin');    // Your MySQL database username
define('DB_PASSWORD', 'cAqrXpN/6tyh0reS');        // Your MySQL database password
define('DB_NAME', 'exam_db'); // The name of your database

// Attempt to connect to MySQL database
$conn = mysqli_connect(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);

// Check connection
if ($conn === false) {
    die("ERROR: Could not connect. " . mysqli_connect_error());
}

// Optional: Set character set to utf8mb4 for better emoji and international character support
mysqli_set_charset($conn, "utf8mb4");

?>
