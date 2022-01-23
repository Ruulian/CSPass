<?php header("Content-Security-Policy: script-src 'self' 'unsafe-inline';"); ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="/style.css">
    <title>CSPass Example 1</title>
</head>
<body>
    <div>
        <form role="search" action="">
            <h1>Exploit unsafe inline</h1>
            <label for="search">Search for stuff</label>
            <input id="search" type="search" name="q" placeholder="Search..." autofocus required />
            <input type="submit" value="Go">
            <?php
                if(isset($_GET["q"])){
                    echo "<p id=\"result\">Result for '" . $_GET["q"] . "'</p>";
                }
            ?>
        </form>
    </div>
</body>
</html>