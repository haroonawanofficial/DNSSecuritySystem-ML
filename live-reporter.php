<!DOCTYPE html>
<html>
<head>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
        }

        h1 {
            color: #333;
            text-align: center;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }

        table, th, td {
            border: 1px solid #333;
        }

        th, td {
            padding: 10px;
            text-align: left;
        }

        th {
            background-color: #333;
            color: white;
        }
    </style>
</head>
<body>
    <h1>DNS Report</h1>

    <h2>Main Domain DNS Records:</h2>
    <?php
    // Replace with PHP code to retrieve and display main domain DNS records from the database
    $host = "your_mysql_host";
    $user = "your_mysql_user";
    $password = "your_mysql_password";
    $database = "dns_data";

    $connection = new mysqli($host, $user, $password, $database);

    if ($connection->connect_error) {
        die("Connection failed: " . $connection->connect_error);
    }

    $query = "SELECT record_type, value FROM dns_records WHERE domain = 'example.com'";
    $result = $connection->query($query);

    if ($result->num_rows > 0) {
        echo "<table>";
        echo "<tr><th>Record Type</th><th>Value</th></tr>";

        while ($row = $result->fetch_assoc()) {
            echo "<tr><td>" . $row["record_type"] . "</td><td>" . $row["value"] . "</td></tr>";
        }

        echo "</table>";
    } else {
        echo "No records found.";
    }

    $connection->close();
    ?>

    <h2>Subdomains:</h2>
    <?php
    // Replace with PHP code to retrieve and display subdomains from the database
    $connection = new mysqli($host, $user, $password, $database);

    if ($connection->connect_error) {
        die("Connection failed: " . $connection->connect_error);
    }

    $query = "SELECT subdomain FROM subdomains";
    $result = $connection->query($query);

    if ($result->num_rows > 0) {
        echo "<table>";
        echo "<tr><th>Subdomain</th></tr>";

        while ($row = $result->fetch_assoc()) {
            echo "<tr><td>" . $row["subdomain"] . "</td></tr>";
        }

        echo "</table>";
    } else {
        echo "No subdomains found.";
    }

    $connection->close();
    ?>

    <h2>Neighboring DNS Servers:</h2>
    <?php
    // Replace with PHP code to retrieve and display neighboring DNS servers from the database
    $connection = new mysqli($host, $user, $password, $database);

    if ($connection->connect_error) {
        die("Connection failed: " . $connection->connect_error);
    }

    $query = "SELECT neighbor_dns FROM neighboring_dns";
    $result = $connection->query($query);

    if ($result->num_rows > 0) {
        echo "<table>";
        echo "<tr><th>Neighboring DNS Server</th></tr>";

        while ($row = $result->fetch_assoc()) {
            echo "<tr><td>" . $row["neighbor_dns"] . "</td></tr>";
        }

        echo "</table>";
    } else {
        echo "No neighboring DNS servers found.";
    }

    $connection->close();
    ?>

<h2>Non-Contiguous IP Space:</h2>
<?php
// Replace with PHP code to retrieve and display non-contiguous IP space information from the database
$connection = new mysqli($host, $user, $password, $database);

if ($connection->connect_error) {
    die("Connection failed: " . $connection->connect_error);
}

$query = "SELECT ip_range, description FROM non_contiguous_ip_space";
$result = $connection->query($query);

if ($result->num_rows > 0) {
    echo "<table>";
    echo "<tr><th>IP Range</th><th>Description</th></tr>";

    while ($row = $result->fetch_assoc()) {
        echo "<tr><td>" . $row["ip_range"] . "</td><td>" . $row["description"] . "</td></tr>";
    }

    echo "</table>";
} else {
    echo "No non-contiguous IP space information found.";
}

$connection->close();
?>

    <h2>DNS Issues:</h2>
    <?php
    // Replace with PHP code to retrieve and display DNS issues from the database
    $connection = new mysqli($host, $user, $password, $database);

    if ($connection->connect_error) {
        die("Connection failed: " . $connection->connect_error);
    }

    $query = "SELECT dns_server, issue_type, description FROM dns_issues";
    $result = $connection->query($query);

    if ($result->num_rows > 0) {
        echo "<table>";
        echo "<tr><th>DNS Server</th><th>Issue Type</th><th>Description</th></tr>";

        while ($row = $result->fetch_assoc()) {
            echo "<tr><td>" . $row["dns_server"] . "</td><td>" . $row["issue_type"] . "</td><td>" . $row["description"] . "</td></tr>";
        }

        echo "</table>";
    } else {
        echo "No DNS issues found.";
    }

    $connection->close();
    ?>
</body>
</html>
